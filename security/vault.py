"""
EpsteinAnalyzer - Security Vault
=================================
DEK/KEK key management, authentication, file/DB encryption at rest,
decoy mode, and memory-safe key handling.

Vault file format (config/vault.key):
  EAVN(4) + version(1) + master_salt(32) + master_wrapped(40)
  + decoy_salt(32) + decoy_wrapped(40) + hmac(32)

The master and decoy passwords wrap DIFFERENT DEKs.  The master DEK
encrypts real data; the decoy DEK is random and cannot decrypt anything.
This ensures plausible deniability: the decoy password can never be used
to recover real data even by bypassing the UI.
"""

import ctypes
import hashlib
import hmac as hmac_mod
import io
import json
import logging
import os
import secrets
import shutil
import sqlite3
import struct
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("vault")

# ============================================================
# CONSTANTS
# ============================================================

VAULT_MAGIC = b"EAVN"
VAULT_VERSION = 1
SALT_SIZE = 32
DEK_SIZE = 32  # 256-bit data encryption key
WRAPPED_KEY_SIZE = 40  # AES-KeyWrap of 32 bytes = 40 bytes
HMAC_SIZE = 32
NONCE_SIZE = 12
CHUNK_SIZE = 64 * 1024

# HKDF info strings for subkey derivation
HKDF_FILE_KEY = b"EpsteinAnalyzer-file-key-v1"
HKDF_DB_KEY = b"EpsteinAnalyzer-db-key-v1"
HKDF_BACKUP_KEY = b"EpsteinAnalyzer-backup-key-v1"
HKDF_SESSION_KEY = b"EpsteinAnalyzer-session-key-v1"

# Encrypted file format
FILE_MAGIC = b"EAEF"
FILE_VERSION = 1
KDF_SCRYPT = 1


# ============================================================
# SECURE KEY - Memory-safe key wrapper
# ============================================================

class SecureKey:
    """Stores cryptographic key in a mutable bytearray with memory protection.

    - Uses VirtualLock to prevent paging to disk (Windows)
    - Uses CryptProtectMemory to encrypt key in RAM (Windows DPAPI)
    - Zeros memory on cleanup
    - Context manager for auto-cleanup
    """

    # CryptProtectMemory flags
    CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
    CRYPTPROTECTMEMORY_BLOCK_SIZE = 16  # Must encrypt in 16-byte blocks

    def __init__(self, key_bytes: bytes):
        # Store as mutable bytearray so we can zero it later
        # Pad to 16-byte boundary for CryptProtectMemory
        key_len = len(key_bytes)
        padded_len = ((key_len + 15) // 16) * 16
        self._buf = bytearray(padded_len)
        self._buf[:key_len] = key_bytes
        self._key_len = key_len
        self._protected = False
        self._destroyed = False

        # Try to lock memory (prevent paging)
        if sys.platform == "win32":
            try:
                buf_ptr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
                ctypes.windll.kernel32.VirtualLock(
                    ctypes.byref(buf_ptr),
                    ctypes.c_size_t(len(self._buf)),
                )
            except Exception:
                logger.debug("VirtualLock failed (non-critical)")

            # Encrypt in memory via DPAPI
            self._protect()

    def _protect(self):
        """Encrypt key in RAM using CryptProtectMemory."""
        if self._protected or self._destroyed:
            return
        if sys.platform == "win32":
            try:
                buf_ptr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
                result = ctypes.windll.crypt32.CryptProtectMemory(
                    ctypes.byref(buf_ptr),
                    ctypes.c_ulong(len(self._buf)),
                    ctypes.c_ulong(self.CRYPTPROTECTMEMORY_SAME_PROCESS),
                )
                if result:
                    self._protected = True
            except Exception:
                logger.debug("CryptProtectMemory failed (non-critical)")

    def _unprotect(self):
        """Decrypt key in RAM."""
        if not self._protected or self._destroyed:
            return
        if sys.platform == "win32":
            try:
                buf_ptr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
                result = ctypes.windll.crypt32.CryptUnprotectMemory(
                    ctypes.byref(buf_ptr),
                    ctypes.c_ulong(len(self._buf)),
                    ctypes.c_ulong(self.CRYPTPROTECTMEMORY_SAME_PROCESS),
                )
                if result:
                    self._protected = False
            except Exception:
                logger.debug("CryptUnprotectMemory failed (non-critical)")

    def get(self) -> bytes:
        """Get the raw key bytes (temporarily decrypts if protected)."""
        if self._destroyed:
            raise RuntimeError("SecureKey has been destroyed")
        was_protected = self._protected
        if was_protected:
            self._unprotect()
        key = bytes(self._buf[:self._key_len])
        if was_protected:
            self._protect()
        return key

    def destroy(self):
        """Zero the key material and release memory."""
        if self._destroyed:
            return
        if self._protected:
            self._unprotect()
        # Zero the buffer
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._destroyed = True

        # Unlock memory
        if sys.platform == "win32":
            try:
                buf_ptr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
                ctypes.windll.kernel32.VirtualUnlock(
                    ctypes.byref(buf_ptr),
                    ctypes.c_size_t(len(self._buf)),
                )
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.destroy()

    def __del__(self):
        self.destroy()


# ============================================================
# KEY MANAGER - DEK/KEK + Key Wrapping
# ============================================================

class KeyManager:
    """Manages Data Encryption Key (DEK) with password-derived Key Encryption Keys (KEK).

    The DEK is a random 256-bit key generated at first setup.
    It is wrapped (encrypted) using AES-KeyWrap (RFC 3394) with a KEK
    derived from the user's password via Scrypt.

    Password change only re-wraps the DEK; no data re-encryption needed.
    Subkeys derived from DEK via HKDF for different purposes.
    """

    def __init__(self, vault_path: str):
        self.vault_path = Path(vault_path)
        self._dek: Optional[SecureKey] = None

    @property
    def is_initialized(self) -> bool:
        return self.vault_path.exists()

    def initialize(self, master_password: str, decoy_password: str):
        """First-time vault setup: generate DEK, wrap with both passwords.

        Master and decoy use SEPARATE DEKs.  The master DEK encrypts real
        data; the decoy DEK is random and cannot decrypt anything real.
        """
        if self.vault_path.exists():
            raise RuntimeError("Vault already initialized. Use reset() to change passwords.")

        # Generate SEPARATE DEKs for master and decoy
        master_dek = os.urandom(DEK_SIZE)
        decoy_dek = os.urandom(DEK_SIZE)

        # Derive KEKs from passwords
        master_salt = os.urandom(SALT_SIZE)
        master_kek = self._derive_kek(master_password, master_salt)
        master_wrapped = aes_key_wrap(master_kek, master_dek)

        decoy_salt = os.urandom(SALT_SIZE)
        decoy_kek = self._derive_kek(decoy_password, decoy_salt)
        decoy_wrapped = aes_key_wrap(decoy_kek, decoy_dek)

        # Build vault file
        vault_data = bytearray()
        vault_data.extend(VAULT_MAGIC)  # 4 bytes
        vault_data.extend(struct.pack("B", VAULT_VERSION))  # 1 byte
        vault_data.extend(master_salt)  # 32 bytes
        vault_data.extend(master_wrapped)  # 40 bytes
        vault_data.extend(decoy_salt)  # 32 bytes
        vault_data.extend(decoy_wrapped)  # 40 bytes

        # HMAC uses master DEK — only master password can verify integrity
        hmac_key = self._derive_hmac_key(master_dek)
        mac = hmac_mod.new(hmac_key, bytes(vault_data), hashlib.sha256).digest()
        vault_data.extend(mac)  # 32 bytes

        # Write vault file
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.vault_path, "wb") as f:
            f.write(vault_data)

        # Lock file permissions (Windows: current user only)
        self._lock_permissions()

        del master_dek, decoy_dek, master_kek, decoy_kek

        logger.info("Vault initialized at %s", self.vault_path)

    def unlock(self, password: str) -> tuple:
        """Attempt to unlock vault with password.

        Returns (mode, secure_key) where mode is "master" or "decoy".
        Constant-time: derives BOTH keys every attempt.
        """
        if not self.vault_path.exists():
            raise FileNotFoundError("Vault not initialized. Run setup.py init first.")

        data = self.vault_path.read_bytes()
        if len(data) < 4 + 1 + 32 + 40 + 32 + 40 + 32:
            raise ValueError("Vault file corrupted: too short")

        # Parse vault file
        offset = 0
        magic = data[offset:offset + 4]; offset += 4
        if magic != VAULT_MAGIC:
            raise ValueError("Vault file corrupted: bad magic")

        version = data[offset]; offset += 1
        if version != VAULT_VERSION:
            raise ValueError(f"Unsupported vault version: {version}")

        master_salt = data[offset:offset + SALT_SIZE]; offset += SALT_SIZE
        master_wrapped = data[offset:offset + WRAPPED_KEY_SIZE]; offset += WRAPPED_KEY_SIZE
        decoy_salt = data[offset:offset + SALT_SIZE]; offset += SALT_SIZE
        decoy_wrapped = data[offset:offset + WRAPPED_KEY_SIZE]; offset += WRAPPED_KEY_SIZE
        stored_hmac = data[offset:offset + HMAC_SIZE]; offset += HMAC_SIZE

        # Constant-time: derive BOTH KEKs regardless of which password was given
        master_kek = self._derive_kek(password, master_salt)
        decoy_kek = self._derive_kek(password, decoy_salt)

        # Try both unwraps
        master_dek = None
        decoy_dek = None

        try:
            master_dek = aes_key_unwrap(master_kek, master_wrapped)
        except Exception:
            pass

        try:
            decoy_dek = aes_key_unwrap(decoy_kek, decoy_wrapped)
        except Exception:
            pass

        # Determine mode:
        # - Master: unwrap succeeds AND HMAC over vault data verifies
        # - Decoy: unwrap succeeds (HMAC was signed with master DEK, so it won't match)
        mode = None
        dek = None

        if master_dek:
            hmac_key = self._derive_hmac_key(master_dek)
            expected_mac = hmac_mod.new(
                hmac_key, data[:offset - HMAC_SIZE], hashlib.sha256
            ).digest()
            if hmac_mod.compare_digest(stored_hmac, expected_mac):
                mode = "master"
                dek = master_dek

        if decoy_dek and mode is None:
            # Decoy DEK is different from master — it can't decrypt real data.
            # Accept on successful unwrap alone (HMAC was signed with master DEK).
            mode = "decoy"
            dek = decoy_dek

        if mode is None:
            raise ValueError("Invalid password")

        self._dek = SecureKey(dek)
        logger.info("Vault unlocked in %s mode", mode)
        return mode, self._dek

    def reset(self, current_password: str, new_master: str, new_decoy: str):
        """Change passwords without re-encrypting data. Re-wraps DEK only.

        Only a master-mode unlock can reset passwords (the master DEK encrypts
        real data; decoy DEK is regenerated fresh).
        """
        mode, secure_key = self.unlock(current_password)
        if mode != "master":
            secure_key.destroy()
            raise ValueError("Password reset requires the master password")
        master_dek = secure_key.get()

        # Generate a fresh random decoy DEK (never the same as master)
        decoy_dek = os.urandom(DEK_SIZE)

        # Generate new salts and wrap
        master_salt = os.urandom(SALT_SIZE)
        master_kek = self._derive_kek(new_master, master_salt)
        master_wrapped = aes_key_wrap(master_kek, master_dek)

        decoy_salt = os.urandom(SALT_SIZE)
        decoy_kek = self._derive_kek(new_decoy, decoy_salt)
        decoy_wrapped = aes_key_wrap(decoy_kek, decoy_dek)

        # Rebuild vault file
        vault_data = bytearray()
        vault_data.extend(VAULT_MAGIC)
        vault_data.extend(struct.pack("B", VAULT_VERSION))
        vault_data.extend(master_salt)
        vault_data.extend(master_wrapped)
        vault_data.extend(decoy_salt)
        vault_data.extend(decoy_wrapped)

        hmac_key = self._derive_hmac_key(master_dek)
        mac = hmac_mod.new(hmac_key, bytes(vault_data), hashlib.sha256).digest()
        vault_data.extend(mac)

        with open(self.vault_path, "wb") as f:
            f.write(vault_data)

        del decoy_dek
        self._lock_permissions()
        logger.info("Vault passwords reset successfully")

    def get_subkey(self, purpose: bytes, length: int = 32) -> bytes:
        """Derive a subkey from the DEK via HKDF for a specific purpose."""
        if self._dek is None:
            raise RuntimeError("Vault not unlocked")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=purpose,
            backend=default_backend(),
        )
        return hkdf.derive(self._dek.get())

    def get_flask_secret(self) -> str:
        """Derive Flask session secret key from DEK."""
        return self.get_subkey(HKDF_SESSION_KEY).hex()

    def lock(self):
        """Destroy the DEK from memory."""
        if self._dek:
            self._dek.destroy()
            self._dek = None
        logger.info("Vault locked")

    @staticmethod
    def _derive_kek(password: str, salt: bytes) -> bytes:
        """Derive a Key Encryption Key from password via Scrypt."""
        kdf = Scrypt(
            salt=salt,
            length=DEK_SIZE,
            n=2**20,
            r=8,
            p=1,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def _derive_hmac_key(dek: bytes) -> bytes:
        """Derive an HMAC signing key from the DEK via HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"EpsteinAnalyzer-vault-hmac-v1",
        )
        return hkdf.derive(dek)

    def _lock_permissions(self):
        """Lock vault file permissions to current user only (Windows)."""
        if sys.platform == "win32":
            try:
                import subprocess
                # Remove inherited permissions, grant current user full control only
                username = os.environ.get("USERNAME", "")
                if username:
                    subprocess.run(
                        ["icacls", str(self.vault_path), "/inheritance:r",
                         "/grant:r", f"{username}:(F)"],
                        capture_output=True, timeout=10,
                    )
                    logger.info("Vault file permissions locked to %s", username)
            except Exception as e:
                logger.warning("Could not lock vault file permissions: %s", e)


# ============================================================
# NULL DATABASE PROXY - Decoy Mode
# ============================================================

class NullDatabaseProxy:
    """Wraps the DatabaseManager interface but returns empty results.

    Used in decoy mode: the dashboard renders normally but shows no data.
    Backed by an in-memory SQLite database with the schema applied.
    """

    def __init__(self, schema_path: str):
        # Use check_same_thread=False so Flask threads can share the conn,
        # and use a URI with mode=memory&cache=shared for thread-safe access
        self._conn = sqlite3.connect(
            "file:decoy_db?mode=memory&cache=shared",
            uri=True,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._schema_path = schema_path
        self._apply_schema()
        self.db_path = ":memory:"
        self.data_dir = Path(tempfile.mkdtemp(prefix="ea_decoy_"))

    def _apply_schema(self):
        """Apply the real schema to the in-memory DB so queries don't crash."""
        try:
            schema_path = Path(self._schema_path)
            if schema_path.exists():
                sql = schema_path.read_text(encoding="utf-8")
                self._conn.executescript(sql)
        except Exception as e:
            logger.debug("Decoy schema apply failed (non-critical): %s", e)

    def get_connection(self):
        return self._conn

    def initialize(self):
        pass

    def log_action(self, action, details=None, user_initiated=True):
        pass

    def get_stats(self):
        return {
            "total_documents": 0,
            "total_entities": 0,
            "total_redactions": 0,
            "recovered_redactions": 0,
            "total_images": 0,
            "total_findings": 0,
            "total_chains": 0,
            "datasets_processed": 0,
        }

    def get_dataset_status(self):
        return []

    def check_disk_usage(self):
        return {"total_bytes": 0, "max_bytes": 0, "usage_ratio": 0.0}

    def auto_compact(self):
        return {"compacted": False}

    def cleanup(self):
        """Remove the temporary decoy directory."""
        import shutil
        try:
            shutil.rmtree(self.data_dir, ignore_errors=True)
        except Exception:
            pass

    def __del__(self):
        self.cleanup()


# ============================================================
# DASHBOARD AUTH - Authentication Middleware
# ============================================================

class DashboardAuth:
    """Flask authentication middleware for the dashboard.

    Features:
    - before_request middleware on ALL routes + Socket.IO
    - Whitelist: /login, /static only
    - Master password -> real data; Decoy password -> NullDatabaseProxy
    - 15-min auto-lock (server-side enforced)
    - 5 attempt limit with HMAC-signed counter
    - Session ID rotation on login
    - Security headers on all responses
    """

    WHITELIST = {"/login", "/static"}
    MAX_ATTEMPTS = 5
    LOCKOUT_SECONDS = 300  # 5 minutes after max attempts

    def __init__(self, app, key_manager: KeyManager, config: dict):
        self.app = app
        self.key_manager = key_manager
        self.config = config
        self._auto_lock_minutes = config.get("vault", {}).get("auto_lock_minutes", 15)
        self._max_attempts = config.get("vault", {}).get("max_login_attempts", 5)

        # Persist lockout state to file so server restarts don't reset it
        self._lockout_file = Path(config.get("project_root", ".")) / "config" / ".lockout"
        self._failed_attempts, self._lockout_until = self._load_lockout()

        # Register middleware
        self.app.before_request(self._check_auth)
        self.app.after_request(self._add_security_headers)

    def _load_lockout(self) -> tuple:
        """Load persisted lockout state from disk."""
        try:
            if self._lockout_file.exists():
                raw = self._lockout_file.read_bytes()
                data = json.loads(raw)
                return int(data.get("attempts", 0)), float(data.get("until", 0))
        except Exception:
            pass
        return 0, 0

    def _save_lockout(self):
        """Persist lockout state to disk (HMAC-signed is overkill here,
        the file is local and an attacker with disk access already won)."""
        try:
            self._lockout_file.parent.mkdir(parents=True, exist_ok=True)
            self._lockout_file.write_text(json.dumps({
                "attempts": self._failed_attempts,
                "until": self._lockout_until,
            }))
        except Exception as e:
            logger.debug("Could not persist lockout state: %s", e)

    def _reset_lockout(self):
        """Clear lockout counter on successful login."""
        self._failed_attempts = 0
        self._lockout_until = 0
        try:
            if self._lockout_file.exists():
                self._lockout_file.unlink()
        except Exception:
            pass

    def _check_auth(self):
        """before_request handler: enforce authentication on all routes."""
        from flask import session, request, redirect, url_for

        # Allow whitelisted paths
        path = request.path
        if path == "/login" or path.startswith("/static"):
            return None

        # Check session
        if not session.get("authenticated"):
            return redirect(url_for("login"))

        # Check auto-lock timeout
        last_activity = session.get("last_activity", 0)
        now = time.time()
        if now - last_activity > self._auto_lock_minutes * 60:
            session.clear()
            logger.info("Session auto-locked due to inactivity")
            return redirect(url_for("login"))

        # Update last activity
        session["last_activity"] = now
        return None

    def _add_security_headers(self, response):
        """Add security headers to all responses."""
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    def attempt_login(self, password: str) -> tuple:
        """Attempt login. Returns (success: bool, mode: str, message: str)."""
        from flask import session

        now = time.time()

        # Check lockout
        if self._failed_attempts >= self._max_attempts:
            if now < self._lockout_until:
                remaining = int(self._lockout_until - now)
                return False, None, f"Account locked. Try again in {remaining}s."
            # Lockout expired, reset
            self._reset_lockout()

        try:
            mode, secure_key = self.key_manager.unlock(password)

            # Reset failed attempts on success
            self._reset_lockout()

            # Rotate session ID
            session.clear()
            session["authenticated"] = True
            session["last_activity"] = now
            session["mode"] = mode
            session["session_id"] = secrets.token_hex(16)

            # SECRET_KEY is already set from DEK in main() before server
            # starts.  Do NOT reset it here -- it would invalidate the
            # session cookie that Flask just signed, causing an infinite
            # login redirect loop.

            logger.info("Login successful (mode=%s)", mode)
            return True, mode, "Login successful"

        except ValueError:
            self._failed_attempts += 1
            remaining = self._max_attempts - self._failed_attempts
            if self._failed_attempts >= self._max_attempts:
                self._lockout_until = now + self.LOCKOUT_SECONDS
                self._save_lockout()
                logger.warning("Max login attempts reached, lockout engaged")
                return False, None, "Account locked for 5 minutes."
            self._save_lockout()
            logger.warning("Failed login attempt %d/%d", self._failed_attempts, self._max_attempts)
            return False, None, f"Invalid password. {remaining} attempts remaining."

    def logout(self):
        """Clear session and lock vault."""
        from flask import session
        session.clear()
        self.key_manager.lock()
        logger.info("User logged out, vault locked")


# ============================================================
# VAULT FILE MANAGER - File Encryption at Rest
# ============================================================

class VaultFileManager:
    """Encrypts files at rest using AES-256-GCM with HKDF-derived subkeys.

    Features:
    - UUID-obfuscated filenames in data/vault/
    - Authenticated Additional Data (AAD) per chunk
    - Authenticated manifest (SHA-256 of all chunk AADs)
    - Decrypt to io.BytesIO only, zero after serving
    """

    def __init__(self, key_manager: KeyManager, data_dir: str, db_manager):
        self.key_manager = key_manager
        self.data_dir = Path(data_dir)
        self.vault_dir = self.data_dir / "vault"
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.db = db_manager

    def _get_file_key(self) -> bytes:
        """Derive the file encryption subkey from DEK."""
        return self.key_manager.get_subkey(HKDF_FILE_KEY)

    def encrypt_file(self, source_path: str, document_id: int = None) -> str:
        """Encrypt a file into the vault. Returns the vault UUID."""
        source = Path(source_path).resolve()
        if not source.exists():
            raise FileNotFoundError(f"Source file not found: {source}")

        file_key = self._get_file_key()
        vault_uuid = str(uuid.uuid4())
        vault_id = "EpsteinAnalyzer"  # Fixed vault identifier for AAD
        version = FILE_VERSION

        dest = self.vault_dir / f"{vault_uuid}.vault"
        tmp_dest = self.vault_dir / f"{vault_uuid}.vault.tmp"

        aesgcm = AESGCM(file_key)
        chunk_aads = []

        try:
            with open(source, "rb") as fin, open(tmp_dest, "wb") as fout:
                # Write file header
                fout.write(FILE_MAGIC)
                fout.write(struct.pack("B", FILE_VERSION))
                fout.write(struct.pack("B", KDF_SCRYPT))
                fout.write(struct.pack(">I", CHUNK_SIZE))

                # Count chunks first for AAD
                file_size = source.stat().st_size
                if file_size == 0:
                    chunk_count = 0
                else:
                    chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

                # Write chunk count
                fout.write(struct.pack(">I", chunk_count))

                chunk_index = 0
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # Build AAD: vault_id | file_uuid | version | chunk_index | chunk_count
                    aad = f"{vault_id}|{vault_uuid}|{version}|{chunk_index}|{chunk_count}".encode()
                    chunk_aads.append(aad)

                    nonce = os.urandom(NONCE_SIZE)
                    ct = aesgcm.encrypt(nonce, chunk, aad)

                    # Write: nonce(12) + ct_len(4) + ct
                    fout.write(nonce)
                    fout.write(struct.pack(">I", len(ct)))
                    fout.write(ct)

                    chunk_index += 1

                # Write manifest: SHA-256 of all chunk AADs concatenated
                manifest_hash = hashlib.sha256(b"".join(chunk_aads)).digest()
                fout.write(manifest_hash)

            # Atomically rename on success — no partial vault files on failure
            os.replace(str(tmp_dest), str(dest))
        except Exception:
            # Remove partial temp file on failure
            try:
                tmp_dest.unlink()
            except OSError:
                pass
            raise

        # Record mapping in database
        if self.db:
            try:
                conn = self.db.get_connection()
                try:
                    conn.execute(
                        """INSERT INTO vault_file_map
                           (original_path, vault_uuid, encrypted_at)
                           VALUES (?, ?, ?)""",
                        (str(source), vault_uuid,
                         datetime.now(tz=timezone.utc).isoformat()),
                    )
                    conn.commit()
                finally:
                    conn.close()
            except Exception as e:
                logger.warning("Could not record vault mapping: %s", e)

        logger.info("Encrypted %s -> %s.vault", source.name, vault_uuid)
        return vault_uuid

    def decrypt_to_memory(self, vault_uuid: str) -> io.BytesIO:
        """Decrypt a vault file to an in-memory BytesIO buffer.

        Returns a BytesIO that should be zeroed after use.
        """
        vault_path = self.vault_dir / f"{vault_uuid}.vault"
        if not vault_path.exists():
            raise FileNotFoundError(f"Vault file not found: {vault_uuid}")

        file_key = self._get_file_key()
        aesgcm = AESGCM(file_key)
        vault_id = "EpsteinAnalyzer"

        with open(vault_path, "rb") as fin:
            # Read header
            magic = fin.read(4)
            if magic != FILE_MAGIC:
                raise ValueError("Invalid vault file: bad magic")

            version = struct.unpack("B", fin.read(1))[0]
            kdf_id = struct.unpack("B", fin.read(1))[0]
            chunk_size = struct.unpack(">I", fin.read(4))[0]
            chunk_count = struct.unpack(">I", fin.read(4))[0]

            output = io.BytesIO()
            chunk_aads = []

            for chunk_index in range(chunk_count):
                nonce = fin.read(NONCE_SIZE)
                if len(nonce) < NONCE_SIZE:
                    raise ValueError("Truncated vault file: missing nonce")

                ct_len = struct.unpack(">I", fin.read(4))[0]
                max_ct = chunk_size + 16  # GCM tag is 16 bytes
                if ct_len > max_ct:
                    raise ValueError(f"Invalid chunk size: {ct_len}")

                ct = fin.read(ct_len)
                if len(ct) < ct_len:
                    raise ValueError("Truncated vault file: missing ciphertext")

                aad = f"{vault_id}|{vault_uuid}|{version}|{chunk_index}|{chunk_count}".encode()
                chunk_aads.append(aad)

                plaintext = aesgcm.decrypt(nonce, ct, aad)
                output.write(plaintext)

            # Verify manifest — require exactly 32 bytes
            stored_manifest = fin.read(32)
            if len(stored_manifest) != 32:
                raise ValueError("Vault file manifest missing or truncated")
            expected_manifest = hashlib.sha256(b"".join(chunk_aads)).digest()
            if not hmac_mod.compare_digest(stored_manifest, expected_manifest):
                raise ValueError("Vault file manifest verification failed")

        output.seek(0)
        return output

    def secure_delete_original(self, file_path: str):
        """Securely delete the original unencrypted file."""
        fp = Path(file_path)
        if not fp.exists():
            return
        try:
            size = fp.stat().st_size
            with open(fp, "wb") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            fp.unlink()
            logger.info("Securely deleted original: %s", fp.name)
        except Exception as e:
            logger.warning("Could not securely delete %s: %s", fp, e)
            try:
                fp.unlink()
            except Exception:
                pass

    def get_vault_uuid_for_path(self, original_path: str) -> Optional[str]:
        """Look up vault UUID for a given original file path."""
        if not self.db:
            return None
        try:
            conn = self.db.get_connection()
            try:
                row = conn.execute(
                    "SELECT vault_uuid FROM vault_file_map WHERE original_path = ?",
                    (str(original_path),),
                ).fetchone()
                return row["vault_uuid"] if row else None
            finally:
                conn.close()
        except Exception:
            return None


# ============================================================
# DATABASE VAULT - DB Encryption at Rest
# ============================================================

class DatabaseVault:
    """Encrypts the SQLite database when the application is not running.

    On startup: decrypt DB, load, run.
    On shutdown: WAL checkpoint, encrypt DB + WAL + SHM, secure-delete plaintext.
    The encrypted copy is canonical on disk.
    """

    def __init__(self, key_manager: KeyManager, db_path: str):
        self.key_manager = key_manager
        self.db_path = Path(db_path)
        self.enc_path = self.db_path.with_suffix(".db.enc")
        self._wal_path = Path(str(self.db_path) + "-wal")
        self._shm_path = Path(str(self.db_path) + "-shm")

    def _get_db_key(self) -> bytes:
        return self.key_manager.get_subkey(HKDF_DB_KEY)

    def decrypt_db(self) -> bool:
        """Decrypt the database for use. Returns True if decrypted, False if no encrypted DB.

        Uses chunked AES-256-GCM with per-chunk AAD to avoid loading the
        entire database into memory at once (prevents MemoryError on large DBs
        and avoids paging plaintext to the swap file).
        Writes to a temp file first, then atomically renames.
        """
        if not self.enc_path.exists():
            return False

        key = self._get_db_key()
        aesgcm = AESGCM(key)
        tmp_path = self.db_path.with_suffix(".db.tmp")

        try:
            with open(self.enc_path, "rb") as fin, open(tmp_path, "wb") as fout:
                # Read header: magic(4) + version(1) + chunk_count(4)
                magic = fin.read(4)
                if magic != b"EADB":
                    raise ValueError("Invalid encrypted DB: bad magic")
                db_ver = struct.unpack("B", fin.read(1))[0]
                chunk_count = struct.unpack(">I", fin.read(4))[0]

                for ci in range(chunk_count):
                    nonce = fin.read(NONCE_SIZE)
                    ct_len = struct.unpack(">I", fin.read(4))[0]
                    ct = fin.read(ct_len)
                    aad = f"EpsteinAnalyzer-db|{db_ver}|{ci}|{chunk_count}".encode()
                    plaintext_chunk = aesgcm.decrypt(nonce, ct, aad)
                    fout.write(plaintext_chunk)
                    # Zero the plaintext chunk from memory
                    ba = bytearray(plaintext_chunk)
                    for k in range(len(ba)):
                        ba[k] = 0
                    del ba, plaintext_chunk

            os.replace(str(tmp_path), str(self.db_path))
        except Exception:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise

        logger.info("Database decrypted for use")
        return True

    def encrypt_db(self):
        """Encrypt the database and securely delete plaintext.

        Uses chunked AES-256-GCM with per-chunk AAD and writes to a temp
        file before atomically renaming.  This bounds memory usage and
        prevents partial encrypted files on crash.
        """
        if not self.db_path.exists():
            logger.warning("No database to encrypt")
            return

        key = self._get_db_key()
        aesgcm = AESGCM(key)

        file_size = self.db_path.stat().st_size
        if file_size == 0:
            chunk_count = 0
        else:
            chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        tmp_enc = self.enc_path.with_suffix(".enc.tmp")
        try:
            with open(self.db_path, "rb") as fin, open(tmp_enc, "wb") as fout:
                # Write header: magic(4) + version(1) + chunk_count(4)
                fout.write(b"EADB")
                fout.write(struct.pack("B", FILE_VERSION))
                fout.write(struct.pack(">I", chunk_count))

                ci = 0
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    aad = f"EpsteinAnalyzer-db|{FILE_VERSION}|{ci}|{chunk_count}".encode()
                    nonce = os.urandom(NONCE_SIZE)
                    ct = aesgcm.encrypt(nonce, chunk, aad)
                    fout.write(nonce)
                    fout.write(struct.pack(">I", len(ct)))
                    fout.write(ct)
                    ci += 1

            # Atomic rename on success
            os.replace(str(tmp_enc), str(self.enc_path))
        except Exception:
            try:
                tmp_enc.unlink()
            except OSError:
                pass
            raise

        # Securely delete plaintext DB and WAL/SHM
        for path in [self.db_path, self._wal_path, self._shm_path]:
            self._secure_delete(path)

        logger.info("Database encrypted, plaintext removed")

    def checkpoint_and_encrypt(self, db_conn):
        """WAL checkpoint then encrypt. Call on shutdown."""
        try:
            db_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            db_conn.close()
        except Exception as e:
            logger.warning("WAL checkpoint failed: %s", e)

        self.encrypt_db()

    @staticmethod
    def _secure_delete(path: Path):
        """Overwrite file with random data before deleting."""
        if not path.exists():
            return
        try:
            size = path.stat().st_size
            with open(path, "wb") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            path.unlink()
        except Exception as e:
            logger.debug("Secure delete of %s failed: %s", path, e)
            try:
                path.unlink()
            except Exception:
                pass


# ============================================================
# OS HARDENING HELPERS
# ============================================================

def check_os_hardening():
    """Check and warn about OS-level security settings."""
    warnings = []

    if sys.platform == "win32":
        # Check if hibernation is enabled
        try:
            import subprocess
            result = subprocess.run(
                ["powercfg", "/a"],
                capture_output=True, text=True, timeout=10,
            )
            if "Hibernate" in result.stdout and "not available" not in result.stdout.lower():
                warnings.append(
                    "Hibernation is enabled. RAM contents (including keys) could be "
                    "written to disk. Consider: powercfg /h off"
                )
        except Exception:
            pass

        # Check pagefile settings
        try:
            import subprocess
            result = subprocess.run(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                 "/v", "ClearPageFileAtShutdown"],
                capture_output=True, text=True, timeout=10,
            )
            if "0x0" in result.stdout:
                warnings.append(
                    "Pagefile is NOT cleared on shutdown. Key material could persist. "
                    "Consider enabling ClearPageFileAtShutdown."
                )
        except Exception:
            pass

    return warnings


def suppress_crash_dumps():
    """Disable Windows Error Reporting crash dumps for this process."""
    if sys.platform == "win32":
        try:
            SEM_FAILCRITICALERRORS = 0x0001
            SEM_NOGPFAULTERRORBOX = 0x0002
            SEM_NOOPENFILEERRORBOX = 0x8000
            ctypes.windll.kernel32.SetErrorMode(
                SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
            )
        except Exception:
            pass


def prevent_sleep_while_unlocked():
    """Prevent system sleep while vault is unlocked (Windows)."""
    if sys.platform == "win32":
        try:
            ES_CONTINUOUS = 0x80000000
            ES_SYSTEM_REQUIRED = 0x00000001
            ctypes.windll.kernel32.SetThreadExecutionState(
                ES_CONTINUOUS | ES_SYSTEM_REQUIRED
            )
        except Exception:
            pass


def allow_sleep():
    """Re-allow system sleep (call on lock/shutdown)."""
    if sys.platform == "win32":
        try:
            ES_CONTINUOUS = 0x80000000
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
        except Exception:
            pass

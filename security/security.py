"""
EpsteinAnalyzer - Security Module
Encryption, integrity monitoring, backups, session wipe, honeypots.
AES-256-GCM encryption at rest with Scrypt key derivation.
"""
import os
import sys
import hmac
import json
import hashlib
import shutil
import secrets
import struct
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("security")

# ============================================================
# ENCRYPTION MANAGER
# ============================================================

class EncryptionManager:
    """AES-256-GCM encryption for files and data at rest."""

    SALT_SIZE = 32
    NONCE_SIZE = 12
    KEY_SIZE = 32  # 256 bits
    CHUNK_SIZE = 64 * 1024  # 64 KB chunks for streaming file encryption

    def __init__(self):
        pass

    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = os.urandom(self.SALT_SIZE)
        kdf = Scrypt(
            salt=salt,
            length=self.KEY_SIZE,
            n=2**20,  # High cost for brute-force resistance
            r=8,
            p=1,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt

    def encrypt_data(self, data: bytes, password: str) -> bytes:
        key, salt = self.derive_key(password)
        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # Format: salt + nonce + ciphertext
        return salt + nonce + ciphertext

    def decrypt_data(self, encrypted: bytes, password: str) -> bytes:
        salt = encrypted[: self.SALT_SIZE]
        nonce = encrypted[self.SALT_SIZE : self.SALT_SIZE + self.NONCE_SIZE]
        ciphertext = encrypted[self.SALT_SIZE + self.NONCE_SIZE :]
        key, _ = self.derive_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_file(self, file_path: str, password: str, output_path: str = None):
        """Encrypt a file using chunked I/O to avoid loading entire file into memory."""
        file_path = Path(file_path)
        if output_path is None:
            output_path = str(file_path) + ".enc"
        key, salt = self.derive_key(password)
        aesgcm = AESGCM(key)
        with open(file_path, "rb") as fin, open(output_path, "wb") as fout:
            fout.write(salt)
            while True:
                chunk = fin.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                nonce = os.urandom(self.NONCE_SIZE)
                ct = aesgcm.encrypt(nonce, chunk, None)
                fout.write(len(ct).to_bytes(4, "big"))
                fout.write(nonce)
                fout.write(ct)
        return output_path

    def decrypt_file(self, file_path: str, password: str, output_path: str = None):
        """Decrypt a file using chunked I/O to avoid loading entire file into memory."""
        file_path = Path(file_path)
        if output_path is None:
            # Properly strip .enc suffix instead of brittle .replace()
            if file_path.suffix == ".enc":
                output_path = str(file_path.with_suffix(""))
            else:
                output_path = str(file_path) + ".dec"
        with open(file_path, "rb") as fin:
            salt = fin.read(self.SALT_SIZE)
            if len(salt) < self.SALT_SIZE:
                raise ValueError("Invalid encrypted file: too short for salt")
            key, _ = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            with open(output_path, "wb") as fout:
                while True:
                    ct_len_bytes = fin.read(4)
                    if not ct_len_bytes:
                        break  # Clean EOF at chunk boundary
                    if len(ct_len_bytes) < 4:
                        raise ValueError("Corrupted encrypted file: truncated chunk header")
                    ct_len = int.from_bytes(ct_len_bytes, "big")
                    max_ct = self.CHUNK_SIZE + 1024  # chunk + GCM tag overhead
                    if ct_len > max_ct:
                        raise ValueError(f"Corrupted encrypted file: chunk size {ct_len} exceeds maximum {max_ct}")
                    nonce = fin.read(self.NONCE_SIZE)
                    if len(nonce) < self.NONCE_SIZE:
                        raise ValueError("Corrupted encrypted file: truncated nonce")
                    ct = fin.read(ct_len)
                    if len(ct) < ct_len:
                        raise ValueError("Corrupted encrypted file: truncated ciphertext")
                    plaintext = aesgcm.decrypt(nonce, ct, None)
                    fout.write(plaintext)
        return output_path


# ============================================================
# INTEGRITY MONITOR
# ============================================================

class IntegrityMonitor:
    """Monitors file integrity using SHA-256 hashes. Detects tampering."""

    def __init__(self, db_manager):
        self.db = db_manager

    def hash_file(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def register_file(self, file_path: str, is_honeypot: bool = False):
        file_path = str(Path(file_path).resolve())
        file_hash = self.hash_file(file_path)
        file_size = os.path.getsize(file_path)
        conn = self.db.get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO file_integrity
                   (file_path, sha256_hash, size_bytes, last_verified_at, is_honeypot)
                   VALUES (?, ?, ?, ?, ?)""",
                (file_path, file_hash, file_size, datetime.now(tz=timezone.utc).isoformat(), is_honeypot),
            )
            conn.commit()
        finally:
            conn.close()

    def verify_all(self) -> dict:
        """Check all registered files for tampering. Run on startup."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute("SELECT * FROM file_integrity").fetchall()

            results = {
                "total_files": len(rows),
                "verified": 0,
                "tampered": [],
                "missing": [],
                "honeypot_triggered": [],
            }

            now = datetime.now(tz=timezone.utc).isoformat()

            for row in rows:
                file_path = row["file_path"]
                if not os.path.exists(file_path):
                    results["missing"].append({
                        "path": file_path,
                        "is_honeypot": bool(row["is_honeypot"]),
                    })
                    continue

                current_hash = self.hash_file(file_path)
                current_size = os.path.getsize(file_path)

                if current_hash != row["sha256_hash"] or current_size != row["size_bytes"]:
                    alert = {
                        "path": file_path,
                        "expected_hash": row["sha256_hash"],
                        "actual_hash": current_hash,
                        "expected_size": row["size_bytes"],
                        "actual_size": current_size,
                        "is_honeypot": bool(row["is_honeypot"]),
                    }

                    if row["is_honeypot"]:
                        results["honeypot_triggered"].append(alert)
                        logger.critical(f"HONEYPOT TRIGGERED: {file_path}")
                    else:
                        results["tampered"].append(alert)
                        logger.warning(f"TAMPER DETECTED: {file_path}")

                    conn.execute(
                        "UPDATE file_integrity SET tamper_detected = 1, tamper_detected_at = ? WHERE file_path = ?",
                        (now, file_path),
                    )
                else:
                    results["verified"] += 1
                    conn.execute(
                        "UPDATE file_integrity SET last_verified_at = ? WHERE file_path = ?",
                        (now, file_path),
                    )

            conn.commit()
        finally:
            conn.close()

        return results


# ============================================================
# HONEYPOT MANAGER
# ============================================================

class HoneypotManager:
    """Creates and monitors decoy files that attract intruders."""

    HONEYPOT_NAMES = [
        "CONFIRMED_NAMES_FINAL.pdf",
        "financial_evidence_KEY.xlsx",
        "witness_testimony_SEALED.docx",
        "flight_log_COMPLETE_decoded.csv",
        "REDACTED_NAMES_RECOVERED.txt",
    ]

    def __init__(self, db_manager, data_dir: str):
        self.db = db_manager
        self.data_dir = Path(data_dir)
        self.integrity = IntegrityMonitor(db_manager)

    def create_honeypots(self):
        """Create convincing-looking decoy files."""
        honeypot_dir = self.data_dir / "findings"  # Hide among real findings

        for name in self.HONEYPOT_NAMES:
            path = honeypot_dir / name
            # Generate realistic-looking but fake content
            fake_content = self._generate_fake_content(name)
            with open(path, "wb") as f:
                f.write(fake_content)
            # Register with integrity monitor
            self.integrity.register_file(str(path), is_honeypot=True)
            logger.info(f"Honeypot created: {path}")

    def _generate_fake_content(self, filename: str) -> bytes:
        """Generate realistic-looking fake data for honeypot files."""
        # Mix of random bytes and plausible-looking text
        header = f"CONFIDENTIAL - {filename}\nGenerated: {datetime.now(tz=timezone.utc).isoformat()}\n\n"
        fake_entries = [
            "Case Reference: SEALED\n",
            "Evidence Classification: HIGH PRIORITY\n",
            "Status: UNDER INVESTIGATION\n",
            "\n[This document contains sensitive information related to ongoing analysis]\n",
            "\n--- DATA FOLLOWS ---\n",
        ]
        content = header + "".join(fake_entries)
        # Pad with random data to make it look like a real document
        padding = os.urandom(4096)
        return content.encode("utf-8") + padding

    def check_honeypots(self) -> list:
        """Check if any honeypot files have been accessed/modified."""
        conn = self.db.get_connection()
        try:
            triggered = conn.execute(
                "SELECT * FROM file_integrity WHERE is_honeypot = 1 AND tamper_detected = 1"
            ).fetchall()
            return [dict(row) for row in triggered]
        finally:
            conn.close()


# ============================================================
# BACKUP MANAGER
# ============================================================

class BackupManager:
    """Encrypted incremental backups to USB or secondary location."""

    def __init__(self, db_manager, data_dir: str):
        self.db = db_manager
        self.data_dir = Path(data_dir)
        self.encryption = EncryptionManager()

    def create_backup(self, backup_path: str, password: str, incremental: bool = True) -> dict:
        """Create encrypted backup of all data."""
        backup_path = Path(backup_path)
        backup_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_name = f"epstein_backup_{timestamp}"
        backup_dir = backup_path / backup_name
        backup_dir.mkdir(parents=True, exist_ok=True)

        files_backed_up = 0
        total_size = 0

        # Determine what to back up
        if incremental:
            last_backup_file = backup_path / ".last_backup"
            last_backup_time = None
            if last_backup_file.exists():
                last_backup_time = datetime.fromisoformat(
                    last_backup_file.read_text().strip()
                )
                # Ensure timezone-aware for comparison with mod_time
                if last_backup_time.tzinfo is None:
                    last_backup_time = last_backup_time.replace(tzinfo=timezone.utc)

        # Resolve dirs to skip during traversal
        backup_dir_resolved = backup_dir.resolve()
        temp_dir_resolved = (self.data_dir / "temp").resolve()

        for file_path in self.data_dir.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip files inside the temp directory (use resolved path, not substring)
            try:
                if file_path.resolve().is_relative_to(temp_dir_resolved):
                    continue
            except (OSError, ValueError):
                pass
            # Skip files inside the backup destination
            try:
                if file_path.resolve().is_relative_to(backup_dir_resolved):
                    continue
            except (OSError, ValueError):
                pass

            # Incremental: only back up files modified since last backup
            if incremental and last_backup_time:
                mod_time = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
                if mod_time < last_backup_time:
                    continue

            # Preserve directory structure
            rel_path = file_path.relative_to(self.data_dir)
            dest = backup_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)

            # Encrypt and copy
            self.encryption.encrypt_file(str(file_path), password, str(dest) + ".enc")
            files_backed_up += 1
            total_size += file_path.stat().st_size

        # Update last backup timestamp
        last_backup_file = backup_path / ".last_backup"
        last_backup_file.write_text(datetime.now(tz=timezone.utc).isoformat())

        # Log the action
        self.db.log_action(
            "backup_created",
            json.dumps({
                "path": str(backup_dir),
                "files": files_backed_up,
                "size_bytes": total_size,
                "incremental": incremental,
            }),
        )

        return {
            "backup_path": str(backup_dir),
            "files_backed_up": files_backed_up,
            "total_size_mb": round(total_size / (1024 ** 2), 1),
            "incremental": incremental,
            "timestamp": timestamp,
        }

    def restore_backup(self, backup_dir: str, password: str, restore_to: str = None) -> dict:
        """Restore from encrypted backup."""
        backup_dir = Path(backup_dir)
        restore_to = Path(restore_to) if restore_to else self.data_dir

        files_restored = 0
        for enc_file in backup_dir.rglob("*.enc"):
            rel_path = enc_file.relative_to(backup_dir)
            # Properly strip .enc suffix
            rel_str = str(rel_path)
            dest = restore_to / (rel_str[:-4] if rel_str.endswith(".enc") else rel_str)
            dest.parent.mkdir(parents=True, exist_ok=True)
            self.encryption.decrypt_file(str(enc_file), password, str(dest))
            files_restored += 1

        self.db.log_action(
            "backup_restored",
            json.dumps({"source": str(backup_dir), "files": files_restored}),
        )

        return {"files_restored": files_restored, "restored_to": str(restore_to)}

    def list_backups(self, backup_path: str) -> list:
        """List all available backups."""
        backup_path = Path(backup_path)
        backups = []
        if backup_path.exists():
            for d in sorted(backup_path.iterdir(), reverse=True):
                if d.is_dir() and d.name.startswith("epstein_backup_"):
                    enc_files = list(d.rglob("*.enc"))
                    total_size = sum(f.stat().st_size for f in enc_files)
                    backups.append({
                        "name": d.name,
                        "path": str(d),
                        "timestamp": d.name.replace("epstein_backup_", ""),
                        "file_count": len(enc_files),
                        "total_size_mb": round(total_size / (1024 ** 2), 1),
                    })
        return backups

    def verify_backup(self, backup_dir: str, password: str) -> dict:
        """Verify backup integrity by attempting to decrypt a sample.

        Uses decrypt_file (chunk-aware) instead of decrypt_data so that
        backups created with chunked encryption are verified correctly.
        """
        backup_dir = Path(backup_dir)
        enc_files = list(backup_dir.rglob("*.enc"))
        if not enc_files:
            return {"valid": False, "error": "No encrypted files found"}

        tested = 0
        errors = []
        for enc_file in enc_files[:3]:
            try:
                dec_path = self.encryption.decrypt_file(str(enc_file), password)
                # Clean up the temporary decrypted file
                Path(dec_path).unlink(missing_ok=True)
                tested += 1
            except Exception as e:
                errors.append({"file": str(enc_file), "error": str(e)})

        return {
            "valid": len(errors) == 0,
            "files_tested": tested,
            "total_files": len(enc_files),
            "errors": errors,
        }


# ============================================================
# SESSION WIPE
# ============================================================

class SessionWiper:
    """Securely wipes temporary data when closing the tool."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)

    def wipe_session(self) -> dict:
        """Wipe all temporary files and clear sensitive data from memory."""
        wiped = 0

        # 1. Clear temp directory with secure overwrite
        temp_dir = self.data_dir / "temp"
        for f in temp_dir.rglob("*"):
            if f.is_file():
                self._secure_delete(f)
                wiped += 1

        # 2. Clear analysis queue processed files
        queue_dir = self.data_dir / "analysis_queue"
        for f in queue_dir.rglob("*.txt"):
            if f.is_file():
                self._secure_delete(f)
                wiped += 1

        # 3. Clear clipboard (Windows)
        try:
            if sys.platform == "win32":
                import subprocess
                subprocess.run(
                    ["powershell", "-Command", "Set-Clipboard -Value $null"],
                    capture_output=True,
                    timeout=5,
                )
        except Exception:
            logger.debug("Clipboard clear failed", exc_info=True)

        return {"files_wiped": wiped}

    def _secure_delete(self, file_path: Path):
        """Overwrite file with random data before deleting."""
        try:
            size = file_path.stat().st_size
            with open(file_path, "wb") as f:
                f.write(os.urandom(size))  # Overwrite with random data
                f.flush()
                os.fsync(f.fileno())
            file_path.unlink()
        except Exception as e:
            logger.warning(f"Could not securely delete {file_path}: {e}")
            try:
                file_path.unlink()
            except Exception:
                pass

    def emergency_wipe(self) -> dict:
        """Emergency wipe of ALL temporary and sensitive processing data.
        Does NOT touch the database or findings — only intermediate files."""
        wiped = 0
        dirs_to_wipe = [
            self.data_dir / "temp",
            self.data_dir / "analysis_queue",
        ]
        for d in dirs_to_wipe:
            if d.exists():
                for f in d.rglob("*"):
                    if f.is_file():
                        self._secure_delete(f)
                        wiped += 1
        return {"files_wiped": wiped, "emergency": True}


# ============================================================
# USB SELF-DESTRUCT (for backup USBs)
# ============================================================

class USBProtection:
    """Tracks failed password attempts on backup decryption."""

    MAX_ATTEMPTS = 3

    def __init__(self, backup_path: str):
        self.backup_path = Path(backup_path)
        self.attempts_file = self.backup_path / ".attempts"

    def _hmac_key(self) -> bytes:
        """Derive a stable HMAC key from the backup path."""
        return hashlib.sha256(str(self.backup_path).encode()).digest()

    def record_attempt(self, success: bool):
        attempts = self._get_attempts()
        if success:
            self._reset_attempts()
            return True

        attempts += 1
        self._write_attempts(attempts)

        if attempts >= self.MAX_ATTEMPTS:
            logger.critical(
                "USB SELF-DESTRUCT: %d failed decrypt attempts on %s — wiping backup",
                attempts, self.backup_path,
            )
            self._self_destruct()
            return False
        return True

    def _write_attempts(self, count: int):
        """Write HMAC-signed attempt counter."""
        data = str(count).encode()
        sig = hmac.new(self._hmac_key(), data, hashlib.sha256).hexdigest()
        self.attempts_file.write_text(f"{count}:{sig}")

    def _get_attempts(self) -> int:
        if self.attempts_file.exists():
            try:
                raw = self.attempts_file.read_text().strip()
                if ":" in raw:
                    count_str, sig = raw.rsplit(":", 1)
                    expected = hmac.new(self._hmac_key(), count_str.encode(), hashlib.sha256).hexdigest()
                    if hmac.compare_digest(sig, expected):
                        return int(count_str)
                    # Tampered — treat as max attempts to trigger wipe
                    logger.critical("USB attempt counter tampered at %s", self.backup_path)
                    return self.MAX_ATTEMPTS
                # Legacy unsigned format — treat as 0 (fresh start)
                return 0
            except (ValueError, OSError):
                return 0
        return 0

    def _reset_attempts(self):
        if self.attempts_file.exists():
            self.attempts_file.unlink()

    def _self_destruct(self):
        """Overwrite all encrypted backup files with random data."""
        logger.critical(f"USB SELF-DESTRUCT triggered at {self.backup_path}")
        for f in self.backup_path.rglob("*.enc"):
            try:
                size = f.stat().st_size
                with open(f, "wb") as fh:
                    fh.write(os.urandom(size))
                f.unlink()
            except Exception:
                logger.debug("Emergency lockout file cleanup failed: %s", f, exc_info=True)
        # Remove the attempts file too
        self._reset_attempts()


# ============================================================
# SECURITY MANAGER (Main Orchestrator)
# ============================================================

class SecurityManager:
    """Main security orchestrator — ties all security components together."""

    def __init__(self, db_manager, data_dir: str):
        self.db = db_manager
        self.data_dir = Path(data_dir)
        self.encryption = EncryptionManager()
        self.integrity = IntegrityMonitor(db_manager)
        self.honeypots = HoneypotManager(db_manager, data_dir)
        self.backup = BackupManager(db_manager, data_dir)
        self.session_wiper = SessionWiper(data_dir)

    def startup_check(self) -> dict:
        """Run all security checks on startup."""
        results = {"timestamp": datetime.now(tz=timezone.utc).isoformat()}

        # 1. Verify file integrity
        integrity_results = self.integrity.verify_all()
        results["integrity"] = integrity_results

        # 2. Check honeypots
        honeypot_alerts = self.honeypots.check_honeypots()
        results["honeypot_alerts"] = honeypot_alerts

        # 3. Overall status
        has_tampering = len(integrity_results.get("tampered", [])) > 0
        has_honeypot_trigger = len(honeypot_alerts) > 0
        has_missing = len(integrity_results.get("missing", [])) > 0

        if has_honeypot_trigger:
            results["status"] = "CRITICAL"
            results["message"] = "HONEYPOT TRIGGERED — Possible unauthorized access detected!"
        elif has_tampering:
            results["status"] = "WARNING"
            results["message"] = f"{len(integrity_results['tampered'])} files modified since last session"
        elif has_missing:
            results["status"] = "ALERT"
            results["message"] = f"{len(integrity_results['missing'])} registered files are missing"
        else:
            results["status"] = "OK"
            results["message"] = f"All {integrity_results['verified']} files verified"

        # Log the check
        self.db.log_action("security_startup_check", json.dumps(results), user_initiated=False)

        return results

    def shutdown(self):
        """Clean shutdown — wipe session data."""
        wipe_results = self.session_wiper.wipe_session()
        self.db.log_action("session_shutdown", json.dumps(wipe_results))
        return wipe_results

    def initialize_security(self):
        """First-time setup — create honeypots, register critical files."""
        self.honeypots.create_honeypots()

        # NOTE: Do NOT register the database for integrity monitoring.
        # The DB file changes every session (inserts, updates) which would
        # trigger false tamper alerts on every startup.

        self.db.log_action("security_initialized", "Honeypots created, integrity baseline set")

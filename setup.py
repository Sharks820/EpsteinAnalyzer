"""
EpsteinAnalyzer - Setup & Initialization
First-time setup, database creation, configuration wizard, and vault management.
"""
import getpass
import os
import sys
import secrets
import subprocess
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

# Prevent .pyc files
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True


def check_prerequisites() -> dict:
    """Check all required tools are installed."""
    results = {}

    # Python
    results["python"] = {
        "installed": True,
        "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }

    # Tesseract
    try:
        r = subprocess.run(["tesseract", "--version"], capture_output=True, text=True, timeout=10)
        results["tesseract"] = {"installed": True, "version": r.stdout.split("\n")[0]}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        results["tesseract"] = {"installed": False, "version": None}

    # AI model CLIs — checked lazily at runtime by PipelineEngine,
    # not at setup time (they can hang, recurse, or spam errors).
    # Just check if the binaries exist on PATH without executing them.
    for cli_name in ("codex", "gemini", "claude", "kimi"):
        import shutil
        found = shutil.which(cli_name) is not None
        results[cli_name] = {"installed": found, "version": "on PATH" if found else None}

    # Git
    try:
        r = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10)
        results["git"] = {"installed": True, "version": r.stdout.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        results["git"] = {"installed": False, "version": None}

    # Node.js
    try:
        r = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=10)
        results["node"] = {"installed": True, "version": r.stdout.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        results["node"] = {"installed": False, "version": None}

    return results


def install_python_deps():
    """Install Python dependencies from requirements.txt."""
    req_file = PROJECT_ROOT / "requirements.txt"
    print("\n[+] Installing Python dependencies...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
        check=True,
    )
    print("[+] Python dependencies installed successfully.")

    # Install spaCy model
    print("\n[+] Installing spaCy NLP model...")
    try:
        subprocess.run(
            [sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
            check=True,
        )
        print("[+] spaCy model installed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Warning: Could not install spaCy model. Entity extraction may be limited.")


def initialize_database():
    """Create and initialize the SQLite database."""
    from database.db import DatabaseManager

    print("\n[+] Initializing database...")
    db = DatabaseManager()
    db.initialize()
    print(f"[+] Database created at: {db.db_path}")
    return db


def initialize_security(db):
    """Set up security layer — honeypots, integrity baseline."""
    from security.security import SecurityManager

    print("\n[+] Initializing security...")
    data_dir = str(Path(db.config["project"]["data_dir"]).resolve())
    security = SecurityManager(db, data_dir)
    security.initialize_security()
    print("[+] Security initialized — honeypots deployed, integrity baseline set.")


def initialize_vault():
    """Set up the security vault with master and decoy passwords."""
    from security.vault import KeyManager, check_os_hardening

    vault_path = PROJECT_ROOT / "config" / "vault.key"

    if vault_path.exists():
        print("\n[!] Vault already initialized at config/vault.key")
        print("    Use 'python setup.py reset-vault' to change passwords.")
        return

    print("\n" + "=" * 60)
    print("  SECURITY VAULT SETUP")
    print("=" * 60)
    print()
    print("  You will set TWO passwords:")
    print("    1. MASTER password  -> unlocks your real data")
    print("    2. DECOY password   -> shows an empty dashboard (plausible deniability)")
    print()

    # Master password
    while True:
        master1 = getpass.getpass("  Master password: ")
        if len(master1) < 8:
            print("  [!] Password must be at least 8 characters.")
            continue
        master2 = getpass.getpass("  Confirm master password: ")
        if master1 != master2:
            print("  [!] Passwords don't match. Try again.")
            continue
        break

    # Decoy password
    while True:
        decoy1 = getpass.getpass("  Decoy password: ")
        if len(decoy1) < 8:
            print("  [!] Password must be at least 8 characters.")
            continue
        if decoy1 == master1:
            print("  [!] Decoy password must differ from master password.")
            continue
        decoy2 = getpass.getpass("  Confirm decoy password: ")
        if decoy1 != decoy2:
            print("  [!] Passwords don't match. Try again.")
            continue
        break

    print("\n  [*] Generating encryption keys (this may take a moment)...")
    key_mgr = KeyManager(str(vault_path))
    key_mgr.initialize(master1, decoy1)

    print("  [+] Vault created at: config/vault.key")
    print("  [+] File permissions locked to current user.")

    # OS hardening warnings
    warnings = check_os_hardening()
    if warnings:
        print("\n  OS Security Recommendations:")
        for w in warnings:
            print(f"    [!] {w}")

    print()


def reset_vault():
    """Change vault passwords without re-encrypting data."""
    from security.vault import KeyManager

    vault_path = PROJECT_ROOT / "config" / "vault.key"

    if not vault_path.exists():
        print("\n[!] No vault found. Run 'python setup.py init' first.")
        return

    print("\n" + "=" * 60)
    print("  VAULT PASSWORD RESET")
    print("=" * 60)
    print()

    current = getpass.getpass("  Current password (master or decoy): ")

    # New master password
    while True:
        master1 = getpass.getpass("  New master password: ")
        if len(master1) < 8:
            print("  [!] Password must be at least 8 characters.")
            continue
        master2 = getpass.getpass("  Confirm new master password: ")
        if master1 != master2:
            print("  [!] Passwords don't match. Try again.")
            continue
        break

    # New decoy password
    while True:
        decoy1 = getpass.getpass("  New decoy password: ")
        if len(decoy1) < 8:
            print("  [!] Password must be at least 8 characters.")
            continue
        if decoy1 == master1:
            print("  [!] Decoy password must differ from master password.")
            continue
        decoy2 = getpass.getpass("  Confirm new decoy password: ")
        if decoy1 != decoy2:
            print("  [!] Passwords don't match. Try again.")
            continue
        break

    print("\n  [*] Re-wrapping encryption key...")
    try:
        key_mgr = KeyManager(str(vault_path))
        key_mgr.reset(current, master1, decoy1)
        print("  [+] Passwords changed successfully.")
        print("  [+] No data re-encryption needed — only the key wrapper was updated.")
    except ValueError as e:
        print(f"  [!] Failed: {e}")
    except Exception as e:
        print(f"  [!] Error: {e}")

    print()


def run_setup():
    """Full first-time setup."""
    print("=" * 60)
    print("  EPSTEIN ANALYZER - FIRST TIME SETUP")
    print("=" * 60)

    # Check prerequisites
    print("\n[*] Checking prerequisites...")
    prereqs = check_prerequisites()
    for tool, info in prereqs.items():
        status = "OK" if info["installed"] else "MISSING"
        version = info["version"] or "N/A"
        icon = "+" if info["installed"] else "!"
        print(f"  [{icon}] {tool}: {status} ({version})")

    missing = [t for t, i in prereqs.items() if not i["installed"] and t != "tesseract"]
    if missing:
        print(f"\n[!] Optional tools not found: {', '.join(missing)}")
        print("    The tool will work but some features may be limited.")

    if not prereqs["tesseract"]["installed"]:
        print("\n[!] WARNING: Tesseract OCR not found!")
        print("    Install from: https://github.com/UB-Mannheim/tesseract/wiki")
        print("    OCR processing will not work without it.")

    # Install deps
    install_python_deps()

    # Initialize database
    db = initialize_database()

    # Initialize security
    initialize_security(db)

    # Initialize vault (password setup)
    initialize_vault()

    # Create initial dataset entries
    print("[+] Creating dataset entries...")
    conn = db.get_connection()
    try:
        for i in range(1, 13):
            conn.execute(
                """INSERT OR IGNORE INTO datasets (dataset_number, source, source_url, status)
                   VALUES (?, 'doj', ?, 'pending')""",
                (i, f"https://www.justice.gov/epstein/doj-disclosures/data-set-{i}-files"),
            )
        conn.commit()
    finally:
        conn.close()
    print("[+] 12 DOJ datasets registered.")

    # Startup hardening check
    if sys.platform == "win32":
        print("\n[*] Startup hardening checks:")
        try:
            result = subprocess.run(
                ["powercfg", "/a"],
                capture_output=True, text=True, timeout=10,
            )
            if "Hibernate" in result.stdout:
                print("  [!] Consider disabling hibernation: powercfg /h off")
        except Exception:
            pass
        print("  [+] PYTHONDONTWRITEBYTECODE=1 set (no .pyc files)")

    print("\n" + "=" * 60)
    print("  SETUP COMPLETE!")
    print("=" * 60)
    print(f"\n  Data directory: {db.data_dir}")
    print(f"  Database: {db.db_path}")
    print(f"\n  To launch the dashboard:")
    print(f"    python -m dashboard.app")
    print(f"\n  To download Dataset 1:")
    print(f"    python -m harvester.harvester --dataset 1")
    print(f"\n  Or use the dashboard buttons for one-click loading.")
    print()


if __name__ == "__main__":
    os.chdir(str(PROJECT_ROOT))
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        run_setup()
    elif len(sys.argv) > 1 and sys.argv[1] == "check":
        prereqs = check_prerequisites()
        for tool, info in prereqs.items():
            status = "OK" if info["installed"] else "MISSING"
            print(f"  {tool}: {status} ({info.get('version', 'N/A')})")
    elif len(sys.argv) > 1 and sys.argv[1] == "reset-vault":
        reset_vault()
    else:
        print("Usage:")
        print("  python setup.py init          - First time setup")
        print("  python setup.py check         - Check prerequisites")
        print("  python setup.py reset-vault   - Change vault passwords")

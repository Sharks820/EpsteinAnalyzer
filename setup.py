"""
EpsteinAnalyzer - Setup & Initialization
First-time setup, database creation, and configuration wizard.
"""
import os
import sys
import secrets
import subprocess
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))


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

    # Codex CLI
    try:
        r = subprocess.run(["codex", "--version"], capture_output=True, text=True, timeout=10)
        results["codex"] = {"installed": True, "version": r.stdout.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        results["codex"] = {"installed": False, "version": None}

    # Gemini CLI
    try:
        r = subprocess.run(["gemini", "--version"], capture_output=True, text=True, timeout=10)
        results["gemini"] = {"installed": True, "version": r.stdout.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        results["gemini"] = {"installed": False, "version": None}

    # Claude CLI
    try:
        r = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=10)
        results["claude"] = {"installed": True, "version": r.stdout.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        results["claude"] = {"installed": False, "version": None}

    # Kimi CLI
    try:
        r = subprocess.run(["kimi", "--version"], capture_output=True, text=True, timeout=10)
        results["kimi"] = {"installed": True, "version": r.stdout.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        results["kimi"] = {"installed": False, "version": None}

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


def generate_secret_key():
    """Generate a secure secret key for Flask."""
    import yaml

    config_path = PROJECT_ROOT / "config" / "settings.yaml"
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    if config["dashboard"]["secret_key"] == "CHANGE_THIS_ON_FIRST_RUN":
        config["dashboard"]["secret_key"] = secrets.token_hex(32)
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        print("[+] Generated secure Flask secret key.")


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

    # Generate secret key
    generate_secret_key()

    # Initialize database
    db = initialize_database()

    # Initialize security
    initialize_security(db)

    # Create initial dataset entries
    print("\n[+] Creating dataset entries...")
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
    else:
        print("Usage:")
        print("  python setup.py init    - First time setup")
        print("  python setup.py check   - Check prerequisites")

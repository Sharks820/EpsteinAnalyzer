"""Quick launcher that starts the dashboard via environment variable (not visible in process list)."""
import subprocess, sys, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

env = os.environ.copy()
env["EA_PASSWORD"] = "epstein123!"

subprocess.run(
    [sys.executable, "dashboard/app.py"],
    cwd=os.path.dirname(os.path.abspath(__file__)),
    env=env,
)

"""Directly trigger processing + analysis on dataset 1 without going through the web API."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from processor.processor import ProcessorEngine
from database.db import DatabaseManager

print("=== Processing Dataset 1 ===")
print("Initializing processor...")

def progress(stage, current, total, message=""):
    pct = int(current / total * 100) if total > 0 else 0
    print(f"  [{pct:3d}%] {stage}: {current}/{total} {message}")

engine = ProcessorEngine(progress_cb=progress)
engine.db.initialize()
result = engine.process_dataset(1)

if result:
    total = result.get("total", 0)
    errors_count = result.get("errors", 0)
    print(f"\nProcessing complete: {total} documents, {errors_count} errors")
else:
    print("\nProcessing returned None")

# Update dataset status
from datetime import datetime, timezone
import sqlite3
conn = sqlite3.connect("data/epstein_analyzer.db")
conn.execute(
    "UPDATE datasets SET status = 'processed', processed_at = ?, updated_at = ? WHERE dataset_number = 1",
    (datetime.now(tz=timezone.utc).isoformat(), datetime.now(tz=timezone.utc).isoformat()),
)
conn.commit()

# Check status after processing
print("\n=== Post-Processing Status ===")
for r in conn.execute("SELECT status, analysis_completed, COUNT(*) FROM documents GROUP BY status, analysis_completed"):
    print(f"  status={r[0]}, analysis_completed={r[1]}, count={r[2]}")
conn.close()
print("\nDone. Documents are now ready for AI analysis.")

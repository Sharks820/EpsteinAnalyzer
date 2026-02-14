"""Run AI analysis on ALL remaining documents in dataset 1, looping until done.
Uses tiered confidence: gemini-flash first, escalate to multi-model only if needed.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from ai_pipeline.pipeline import PipelineEngine
from datetime import datetime, timezone
import sqlite3

print("=== AI Analysis - Dataset 1 (Tiered Confidence) ===")
print("Strategy: gemini-flash first -> escalate if quality < 88%")

batch = 0
total_successes = 0
total_errors = 0

while True:
    batch += 1
    print(f"\n--- Batch {batch} ---")

    engine = PipelineEngine()

    def progress(current, total, doc_id, status):
        pct = round(current / total * 100) if total else 0
        print(f"  [{pct:3d}%] Doc {doc_id}: {status} ({current}/{total})")

    engine.progress_callback = progress
    results = engine.analyze_dataset(1)

    if not results:
        print(f"  No more documents to analyze.")
        break

    successes = sum(1 for r in results if "error" not in r)
    errors = len(results) - successes
    total_successes += successes
    total_errors += errors
    print(f"  Batch {batch}: {successes} succeeded, {errors} failed out of {len(results)}")

# Update dataset status
conn = sqlite3.connect("data/epstein_analyzer.db")
conn.execute(
    "UPDATE datasets SET status = 'analyzed', updated_at = ? WHERE dataset_number = 1",
    (datetime.now(tz=timezone.utc).isoformat(),),
)
conn.commit()

# Final status check
print(f"\n=== TOTAL: {total_successes} succeeded, {total_errors} failed ===")
print("\n=== Final Document Status ===")
for r in conn.execute("SELECT status, analysis_completed, COUNT(*) FROM documents GROUP BY status, analysis_completed"):
    print(f"  status={r[0]}, analysis_completed={r[1]}, count={r[2]}")

print("\n=== Entity/Relationship Counts ===")
ent_count = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
rel_count = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
red_count = conn.execute("SELECT COUNT(*) FROM redactions").fetchone()[0]
ai_count = conn.execute("SELECT COUNT(*) FROM ai_analyses").fetchone()[0]
print(f"  Entities: {ent_count}")
print(f"  Relationships: {rel_count}")
print(f"  Redactions: {red_count}")
print(f"  AI Analyses: {ai_count}")
conn.close()
print("\nDone!")

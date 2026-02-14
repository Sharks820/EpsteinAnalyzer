"""Reset any documents that got stuck during the failed analysis attempt."""
import sqlite3
conn = sqlite3.connect("data/epstein_analyzer.db")

# Check current state
print("=== Current Status ===")
for r in conn.execute("SELECT status, analysis_completed, COUNT(*) FROM documents GROUP BY status, analysis_completed"):
    print(f"  status={r[0]}, analysis_completed={r[1]}, count={r[2]}")

# Reset any that got marked as 'analyzing' or partially processed back to 'ocr_complete'
result = conn.execute(
    "UPDATE documents SET status = 'ocr_complete', analysis_completed = 0 WHERE status IN ('analyzing', 'analyzed') AND analysis_completed = 0"
)
print(f"\nReset {result.rowcount} docs from analyzing/analyzed back to ocr_complete")

# Also reset dataset status back to 'processed'
conn.execute("UPDATE datasets SET status = 'processed' WHERE dataset_number = 1 AND status != 'processed'")
conn.commit()

print("\n=== After Reset ===")
for r in conn.execute("SELECT status, analysis_completed, COUNT(*) FROM documents GROUP BY status, analysis_completed"):
    print(f"  status={r[0]}, analysis_completed={r[1]}, count={r[2]}")
conn.close()

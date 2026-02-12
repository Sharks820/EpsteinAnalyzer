"""
EpsteinAnalyzer - Database Manager
Handles SQLite initialization, connections, and disk management.
"""
import sqlite3
import os
import hashlib
import shutil
import yaml
from pathlib import Path
from datetime import datetime, timezone

DB_NAME = "epstein_analyzer.db"


class DatabaseManager:
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.data_dir = Path(self.config["project"]["data_dir"]).resolve()
        self.db_path = self.data_dir / DB_NAME
        self.max_bytes = self.config["project"]["max_disk_gb"] * (1024 ** 3)
        self.compact_threshold = self.config["project"]["auto_compact_threshold"]
        self._ensure_dirs()

    def _load_config(self, config_path: str = None) -> dict:
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "settings.yaml"
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def _ensure_dirs(self):
        dirs = [
            self.data_dir,
            self.data_dir / "datasets",
            self.data_dir / "analysis_queue",
            self.data_dir / "findings",
            self.data_dir / "backups",
            self.data_dir / "honeypots",
            self.data_dir / "temp",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        return conn

    def initialize(self):
        schema_path = Path(__file__).parent / "schema.sql"
        with open(schema_path, "r") as f:
            schema_sql = f.read()
        conn = self.get_connection()
        try:
            conn.executescript(schema_sql)
            conn.commit()
            # Initialize disk usage tracking
            conn.execute(
                "INSERT OR IGNORE INTO disk_usage (id, total_bytes, max_bytes, compact_threshold) VALUES (1, 0, ?, ?)",
                (self.max_bytes, self.compact_threshold),
            )
            conn.commit()
        finally:
            conn.close()

    def check_disk_usage(self) -> dict:
        total = 0
        for path in self.data_dir.rglob("*"):
            if path.is_file():
                total += path.stat().st_size
        usage_pct = total / self.max_bytes if self.max_bytes > 0 else 0
        needs_compact = usage_pct >= self.compact_threshold

        conn = self.get_connection()
        try:
            conn.execute(
                "UPDATE disk_usage SET total_bytes = ?, measured_at = ? WHERE id = 1",
                (total, datetime.now(tz=timezone.utc).isoformat()),
            )
            conn.commit()
        finally:
            conn.close()

        return {
            "total_bytes": total,
            "total_gb": round(total / (1024 ** 3), 2),
            "max_gb": self.config["project"]["max_disk_gb"],
            "usage_percent": round(usage_pct * 100, 1),
            "needs_compact": needs_compact,
            "compact_threshold_percent": self.compact_threshold * 100,
        }

    def auto_compact(self) -> dict:
        """Remove temp files, compress analyzed data, flag low-value docs for review."""
        freed = 0
        actions = []

        # 1. Clear temp directory
        temp_dir = self.data_dir / "temp"
        for f in temp_dir.rglob("*"):
            if f.is_file():
                size = f.stat().st_size
                f.unlink()
                freed += size
        actions.append(f"Cleared temp directory")

        # 2. Clear analysis queue for already-processed docs
        queue_dir = self.data_dir / "analysis_queue"
        conn = self.get_connection()
        try:
            analyzed = conn.execute(
                "SELECT file_hash FROM documents WHERE status = 'analyzed'"
            ).fetchall()
            analyzed_hashes = {row["file_hash"] for row in analyzed}
        finally:
            conn.close()

        for f in queue_dir.rglob("*"):
            if f.is_file():
                file_hash = hashlib.sha256(f.read_bytes()).hexdigest()
                if file_hash in analyzed_hashes:
                    size = f.stat().st_size
                    f.unlink()
                    freed += size
        actions.append(f"Cleared processed analysis queue files")

        # 3. Flag low-priority unreviewed docs for deletion queue
        conn = self.get_connection()
        try:
            low_priority = conn.execute(
                """SELECT id FROM documents
                   WHERE priority_score < 10
                   AND status = 'analyzed'
                   AND user_reviewed = 0
                   AND id NOT IN (SELECT document_id FROM deletion_queue)"""
            ).fetchall()
            for doc in low_priority:
                conn.execute(
                    """INSERT INTO deletion_queue (document_id, reason, ai_assessment, user_decision)
                       VALUES (?, 'Auto-compact: low priority score', ?, 'pending')""",
                    (doc["id"], f"Flagged during auto-compact at {round(self.compact_threshold * 100)}% disk usage"),
                )
            conn.commit()
            actions.append(f"Flagged {len(low_priority)} low-priority docs for your review")
        finally:
            conn.close()

        return {
            "freed_bytes": freed,
            "freed_mb": round(freed / (1024 ** 2), 1),
            "actions": actions,
        }

    def log_action(self, action: str, details: str = None, user_initiated: bool = True):
        conn = self.get_connection()
        try:
            conn.execute(
                "INSERT INTO audit_log (action, details, user_initiated) VALUES (?, ?, ?)",
                (action, details, user_initiated),
            )
            conn.commit()
        finally:
            conn.close()

    def get_dataset_status(self) -> list:
        conn = self.get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM datasets ORDER BY dataset_number"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_stats(self) -> dict:
        conn = self.get_connection()
        try:
            stats = {}
            stats["total_documents"] = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            stats["processed_documents"] = conn.execute("SELECT COUNT(*) FROM documents WHERE analysis_completed = 1").fetchone()[0]
            stats["total_entities"] = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
            stats["total_relationships"] = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
            stats["total_redactions"] = conn.execute("SELECT COUNT(*) FROM redactions").fetchone()[0]
            stats["recovered_redactions"] = conn.execute("SELECT COUNT(*) FROM redactions WHERE is_recovered = 1").fetchone()[0]
            stats["total_email_chains"] = conn.execute("SELECT COUNT(*) FROM email_chains").fetchone()[0]
            stats["total_findings"] = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            stats["removed_files_detected"] = conn.execute("SELECT COUNT(*) FROM removed_files").fetchone()[0]
            stats["removed_files_recovered"] = conn.execute("SELECT COUNT(*) FROM removed_files WHERE recovered = 1").fetchone()[0]
            stats["pending_image_reviews"] = conn.execute("SELECT COUNT(*) FROM images WHERE user_reviewed = 0 AND recovery_successful = 1").fetchone()[0]
            stats["pending_deletions"] = conn.execute("SELECT COUNT(*) FROM deletion_queue WHERE user_decision = 'pending'").fetchone()[0]
            disk = self.check_disk_usage()
            stats["disk_usage_gb"] = disk["total_gb"]
            stats["disk_usage_percent"] = disk["usage_percent"]
            stats["needs_compact"] = disk["needs_compact"]
            return stats
        finally:
            conn.close()

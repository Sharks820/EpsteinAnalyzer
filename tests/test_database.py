"""
Tests for the database layer — schema creation, connections, disk management.
"""
import sqlite3
import pytest


class TestDatabaseInit:
    """Verify schema creation and table structure."""

    def test_tables_created(self, db_conn):
        tables = {
            row[0]
            for row in db_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        expected = {
            "datasets", "documents", "document_pages",
            "redactions", "images", "entities", "relationships",
            "entity_document_links", "email_chains", "email_messages",
            "findings", "deletion_queue", "ai_analyses", "ai_consensus",
            "file_integrity", "audit_log", "disk_usage", "removed_files",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"

    def test_fts5_tables_created(self, db_conn):
        tables = {
            row[0]
            for row in db_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "document_text_fts" in tables
        assert "entities_fts" in tables

    def test_row_factory(self, db_conn):
        assert db_conn.row_factory is sqlite3.Row

    def test_wal_journal(self, db_conn):
        mode = db_conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"

    def test_foreign_keys_enabled(self, db_conn):
        fk = db_conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1

    def test_disk_usage_initialized(self, db_conn):
        row = db_conn.execute("SELECT * FROM disk_usage WHERE id = 1").fetchone()
        assert row is not None
        assert row["max_bytes"] > 0

    def test_insert_dataset(self, db_conn):
        db_conn.execute(
            "INSERT INTO datasets (dataset_number, source, source_url) VALUES (?, ?, ?)",
            (1, "doj", "https://example.com/dataset1"),
        )
        db_conn.commit()
        row = db_conn.execute("SELECT * FROM datasets WHERE dataset_number = 1").fetchone()
        assert row is not None
        assert row["source"] == "doj"

    def test_document_status_check_constraint(self, db_conn):
        db_conn.execute(
            "INSERT INTO datasets (dataset_number, source) VALUES (99, 'test')"
        )
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, file_path, source, status) "
            "VALUES (1, 'abc123', 'test.pdf', '/tmp/test.pdf', 'doj', 'pending')"
        )
        db_conn.commit()
        # Invalid status should fail
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                "INSERT INTO documents (dataset_id, file_hash, original_filename, file_path, source, status) "
                "VALUES (1, 'def456', 'test2.pdf', '/tmp/test2.pdf', 'doj', 'INVALID_STATUS')"
            )


class TestDiskUsage:
    def test_check_disk_usage(self, db_manager, tmp_data_dir):
        # Create a dummy file to have non-zero usage
        dummy = tmp_data_dir / "datasets" / "dummy.bin"
        dummy.write_bytes(b"\x00" * 1024)
        result = db_manager.check_disk_usage()
        assert result["total_bytes"] >= 1024
        assert "usage_percent" in result

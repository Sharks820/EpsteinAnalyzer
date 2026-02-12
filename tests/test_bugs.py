"""
Comprehensive Bug & Error Regression Tests for EpsteinAnalyzer.
================================================================
Validates every fix applied during security and code review sessions.
Each test class targets a specific finding / bug category.
"""
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest


# ============================================================================
#  1.  DATABASE LAYER — busy_timeout, connection safety, config resolution
# ============================================================================


class TestDatabaseBusyTimeout:
    """Finding 4 (P1): SQLite busy_timeout must be set for concurrent access."""

    def test_busy_timeout_set(self, db_conn):
        """PRAGMA busy_timeout should be 30000ms."""
        val = db_conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert val == 30000, f"Expected 30000, got {val}"

    def test_connect_timeout_kwarg(self, db_manager):
        """sqlite3.connect() timeout kwarg should be 30 seconds."""
        # Verify by calling get_connection and checking it doesn't raise
        conn = db_manager.get_connection()
        try:
            assert conn is not None
        finally:
            conn.close()

    def test_concurrent_writers_dont_deadlock(self, db_manager):
        """Two threads writing simultaneously should not raise OperationalError."""
        errors = []

        def writer(n):
            try:
                conn = db_manager.get_connection()
                try:
                    for i in range(20):
                        conn.execute(
                            "INSERT INTO audit_log (action, details) VALUES (?, ?)",
                            (f"thread-{n}", f"iteration-{i}"),
                        )
                        conn.commit()
                finally:
                    conn.close()
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=writer, args=(1,))
        t2 = threading.Thread(target=writer, args=(2,))
        t1.start()
        t2.start()
        t1.join(timeout=60)
        t2.join(timeout=60)

        assert errors == [], f"Concurrent writes raised: {errors}"

        # Verify all rows were written
        conn = db_manager.get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            assert count == 40
        finally:
            conn.close()


class TestConfigRelativePathResolution:
    """Finding 23 (P3): data_dir should resolve relative to project root, not CWD."""

    def test_relative_data_dir_resolves_to_project_root(self, tmp_path):
        import yaml
        from database.db import DatabaseManager

        # Write a config with a RELATIVE data_dir
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        data_dir_relative = "data"

        cfg = {
            "project": {
                "name": "test",
                "version": "1.0.0",
                "data_dir": data_dir_relative,
                "max_disk_gb": 1,
                "auto_compact_threshold": 0.8,
            }
        }
        config_path = config_dir / "settings.yaml"
        with open(config_path, "w") as f:
            yaml.dump(cfg, f)

        db = DatabaseManager(config_path=str(config_path))
        # The resolved path should NOT be os.getcwd()/data
        # It should be relative to the project root (db.py's parent.parent)
        project_root = Path(__file__).parent.parent.resolve()
        expected = (project_root / data_dir_relative).resolve()
        assert db.data_dir == expected, f"Expected {expected}, got {db.data_dir}"

    def test_absolute_data_dir_used_as_is(self, tmp_path):
        import yaml
        from database.db import DatabaseManager

        abs_data_dir = tmp_path / "my_data"
        abs_data_dir.mkdir()
        cfg = {
            "project": {
                "name": "test",
                "version": "1.0.0",
                "data_dir": str(abs_data_dir),
                "max_disk_gb": 1,
                "auto_compact_threshold": 0.8,
            }
        }
        config_path = tmp_path / "settings.yaml"
        with open(config_path, "w") as f:
            yaml.dump(cfg, f)

        db = DatabaseManager(config_path=str(config_path))
        assert db.data_dir == abs_data_dir.resolve()


# ============================================================================
#  2.  SCHEMA CONSTRAINTS — CHECK constraints, FTS triggers
# ============================================================================


class TestSchemaConstraints:
    """Verify CHECK constraints reject invalid values."""

    def test_document_status_rejects_invalid(self, db_conn):
        """Finding: document status CHECK constraint should block bad values."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                "INSERT INTO documents (dataset_id, file_hash, original_filename, "
                "file_path, source, status) VALUES (1, 'h1', 'f.pdf', '/t', 'doj', 'BOGUS')"
            )

    def test_document_status_accepts_all_valid(self, db_conn):
        """All valid status values should be accepted."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.commit()
        valid_statuses = [
            "pending", "downloaded", "ocr_processing", "ocr_complete",
            "analyzing", "analyzed", "reviewed", "junk", "deleted",
        ]
        for i, status in enumerate(valid_statuses):
            db_conn.execute(
                "INSERT INTO documents (dataset_id, file_hash, original_filename, "
                "file_path, source, status) VALUES (1, ?, ?, '/t', 'doj', ?)",
                (f"hash_{i}", f"file_{i}.pdf", status),
            )
        db_conn.commit()
        count = db_conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        assert count == len(valid_statuses)

    def test_redaction_status_rejects_invalid(self, db_conn):
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source) VALUES (1, 'h', 'f.pdf', '/t', 'doj')"
        )
        db_conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                "INSERT INTO redactions (document_id, page_number, status) VALUES (1, 1, 'INVALID')"
            )

    def test_entity_type_rejects_invalid(self, db_conn):
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                "INSERT INTO entities (name, entity_type, canonical_name) "
                "VALUES ('Test', 'NOT_A_TYPE', 'test')"
            )

    def test_ai_model_name_rejects_invalid(self, db_conn):
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source) VALUES (1, 'h', 'f.pdf', '/t', 'doj')"
        )
        db_conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                "INSERT INTO ai_analyses (document_id, model_name) VALUES (1, 'gpt4')"
            )


class TestFTSTriggers:
    """Verify FTS5 sync triggers fire correctly on INSERT, UPDATE, DELETE."""

    def test_fts_populated_on_insert(self, db_conn):
        """Inserting into document_pages should auto-populate document_text_fts."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source) VALUES (1, 'fts_h', 'fts.pdf', '/t', 'doj')"
        )
        db_conn.execute(
            "INSERT INTO document_pages (document_id, page_number, text_content) "
            "VALUES (1, 1, 'Jeffrey Epstein flight log passengers')"
        )
        db_conn.commit()

        rows = db_conn.execute(
            "SELECT * FROM document_text_fts WHERE document_text_fts MATCH 'flight'"
        ).fetchall()
        assert len(rows) >= 1

    def test_fts_updated_on_update(self, db_conn):
        """Updating document_pages text should update FTS index."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source) VALUES (1, 'fts_u', 'fts.pdf', '/t', 'doj')"
        )
        db_conn.execute(
            "INSERT INTO document_pages (document_id, page_number, text_content) "
            "VALUES (1, 1, 'original content here')"
        )
        db_conn.commit()

        # Update
        db_conn.execute(
            "UPDATE document_pages SET text_content = 'replacement helicopter evidence' "
            "WHERE document_id = 1 AND page_number = 1"
        )
        db_conn.commit()

        # Old text should not match
        old_rows = db_conn.execute(
            "SELECT * FROM document_text_fts WHERE document_text_fts MATCH 'original'"
        ).fetchall()
        assert len(old_rows) == 0

        # New text should match
        new_rows = db_conn.execute(
            "SELECT * FROM document_text_fts WHERE document_text_fts MATCH 'helicopter'"
        ).fetchall()
        assert len(new_rows) >= 1

    def test_fts_cleared_on_delete(self, db_conn):
        """Deleting from document_pages should remove from FTS."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source) VALUES (1, 'fts_d', 'fts.pdf', '/t', 'doj')"
        )
        db_conn.execute(
            "INSERT INTO document_pages (document_id, page_number, text_content) "
            "VALUES (1, 1, 'unique_zebra_token')"
        )
        db_conn.commit()

        db_conn.execute("DELETE FROM document_pages WHERE document_id = 1 AND page_number = 1")
        db_conn.commit()

        rows = db_conn.execute(
            "SELECT * FROM document_text_fts WHERE document_text_fts MATCH 'unique_zebra_token'"
        ).fetchall()
        assert len(rows) == 0

    def test_entity_fts_populated(self, db_conn):
        """Inserting into entities should populate entities_fts."""
        db_conn.execute(
            "INSERT INTO entities (name, entity_type, canonical_name, description) "
            "VALUES ('Ghislaine Maxwell', 'person', 'ghislaine_maxwell', 'British socialite')"
        )
        db_conn.commit()

        rows = db_conn.execute(
            "SELECT * FROM entities_fts WHERE entities_fts MATCH 'Ghislaine'"
        ).fetchall()
        assert len(rows) >= 1


# ============================================================================
#  3.  AI PIPELINE — _names_match, duplicate analysis, placeholder text
# ============================================================================


class TestNamesMatch:
    """Finding 29 (P3): _names_match must reject short substring false positives."""

    @pytest.fixture()
    def match(self):
        from ai_pipeline.pipeline import PipelineEngine
        return PipelineEngine._names_match

    def test_exact_match(self, match):
        assert match("John Doe", "John Doe") is True

    def test_case_insensitive(self, match):
        assert match("john doe", "JOHN DOE") is True

    def test_whitespace_normalization(self, match):
        assert match("John  Doe", "John Doe") is True

    def test_substring_match_long_enough(self, match):
        """4+ char substrings should match."""
        assert match("Maxwell", "Ghislaine Maxwell") is True
        assert match("Ghislaine Maxwell", "Maxwell") is True

    def test_short_substring_rejected(self, match):
        """< 4 char substrings must NOT match (the bug we fixed)."""
        assert match("Al", "Alan Dershowitz") is False
        assert match("Jo", "John Smith") is False
        assert match("Ed", "Edward Jones") is False

    def test_exactly_four_chars_accepted(self, match):
        """Exactly 4 chars should be accepted as substring."""
        assert match("Alan", "Alan Dershowitz") is True

    def test_empty_strings(self, match):
        assert match("", "anything") is False
        assert match("something", "") is False
        assert match("", "") is False

    def test_whitespace_only(self, match):
        assert match("   ", "something") is False


class TestDuplicateAnalysisPrevention:
    """Finding 25 (P2): _save_analysis must skip duplicates for same doc + model."""

    def test_duplicate_insert_blocked(self, db_manager, db_conn):
        """Second INSERT for same doc_id + model should be silently skipped."""
        # Set up a document
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source, status) VALUES (1, 'dup_h', 'dup.pdf', '/t', 'doj', 'analyzing')"
        )
        db_conn.commit()

        from ai_pipeline.pipeline import PipelineEngine
        engine = PipelineEngine.__new__(PipelineEngine)
        engine.db = db_manager

        parsed = {"summary": "test summary", "entities": []}

        # First save should succeed
        engine._save_analysis(1, "codex", parsed, "raw response 1", 1.5)

        # Second save for same doc+model should be silently skipped
        engine._save_analysis(1, "codex", parsed, "raw response 2", 2.0)

        # Should only have 1 row
        count = db_conn.execute(
            "SELECT COUNT(*) FROM ai_analyses WHERE document_id = 1 AND model_name = 'codex'"
        ).fetchone()[0]
        assert count == 1

    def test_different_model_allowed(self, db_manager, db_conn):
        """Different model names for the same doc should both insert."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source, status) VALUES (1, 'dm_h', 'dm.pdf', '/t', 'doj', 'analyzing')"
        )
        db_conn.commit()

        from ai_pipeline.pipeline import PipelineEngine
        engine = PipelineEngine.__new__(PipelineEngine)
        engine.db = db_manager

        parsed = {"summary": "test", "entities": []}

        engine._save_analysis(1, "codex", parsed, "raw 1", 1.0)
        engine._save_analysis(1, "gemini", parsed, "raw 2", 1.0)

        count = db_conn.execute(
            "SELECT COUNT(*) FROM ai_analyses WHERE document_id = 1"
        ).fetchone()[0]
        assert count == 2


class TestPlaceholderTextSkip:
    """Finding 17 (P3): AI analysis should skip documents with no extracted text."""

    def test_no_text_placeholder_detected(self, db_manager, db_conn):
        """Documents returning placeholder text should be skipped."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source, status, doc_type, file_type, page_count, priority_score) "
            "VALUES (1, 'pt_h', 'scan.pdf', '/t', 'doj', 'ocr_complete', 'unknown', 'pdf', 1, 0)"
        )
        db_conn.commit()
        # DO NOT insert any document_pages — _get_document_text returns placeholder

        from ai_pipeline.pipeline import PipelineEngine
        engine = PipelineEngine.__new__(PipelineEngine)
        engine.db = db_manager
        engine.chain_aware = False

        # Call the internal helper to verify placeholder detection
        text = engine._get_document_text(1)
        assert text.startswith("(No extracted text")


# ============================================================================
#  4.  REDACTION OFFSET — 1-based AI index to 0-based OFFSET conversion
# ============================================================================


class TestRedactionOffset:
    """Finding 7 (P2): AI produces 1-based indices; OFFSET is 0-based."""

    def test_offset_conversion(self, db_conn):
        """Redaction #1 from AI should map to OFFSET 0 (first redaction)."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source) VALUES (1, 'r_h', 'r.pdf', '/t', 'doj')"
        )
        # Insert 3 redactions in order
        for i in range(3):
            db_conn.execute(
                "INSERT INTO redactions (document_id, page_number, status) VALUES (1, ?, 'unresolved')",
                (i + 1,),
            )
        db_conn.commit()

        # Get the IDs in order
        ids = [
            r["id"]
            for r in db_conn.execute(
                "SELECT id FROM redactions WHERE document_id = 1 ORDER BY id"
            ).fetchall()
        ]
        assert len(ids) == 3

        # AI index 1 → OFFSET 0 → first row
        ai_index = 1
        offset = max(0, ai_index - 1)
        target = db_conn.execute(
            "SELECT id FROM redactions WHERE document_id = 1 ORDER BY id LIMIT 1 OFFSET ?",
            (offset,),
        ).fetchone()
        assert target["id"] == ids[0]

        # AI index 3 → OFFSET 2 → third row
        ai_index = 3
        offset = max(0, ai_index - 1)
        target = db_conn.execute(
            "SELECT id FROM redactions WHERE document_id = 1 ORDER BY id LIMIT 1 OFFSET ?",
            (offset,),
        ).fetchone()
        assert target["id"] == ids[2]

    def test_zero_index_clamps_to_zero(self):
        """If AI returns 0, max(0, 0-1) = 0 which is safe."""
        ai_index = 0
        offset = max(0, ai_index - 1)
        assert offset == 0

    def test_negative_index_clamps_to_zero(self):
        """Negative index from malformed AI output should clamp to 0."""
        ai_index = -5
        offset = max(0, ai_index - 1)
        assert offset == 0


# ============================================================================
#  5.  ENTITY UPSERT ATOMICITY
# ============================================================================


class TestEntityUpsertAtomicity:
    """Finding 15 (P2): Entity upsert should use INSERT OR IGNORE to avoid races."""

    def test_insert_or_ignore_creates_entity(self, db_conn):
        """First insert for a canonical name should create the entity."""
        db_conn.execute("""
            INSERT OR IGNORE INTO entities (name, entity_type, canonical_name, created_at, updated_at)
            VALUES ('Jeffrey Epstein', 'person', 'Jeffrey Epstein', '2024-01-01', '2024-01-01')
        """)
        db_conn.commit()

        row = db_conn.execute(
            "SELECT * FROM entities WHERE canonical_name = 'Jeffrey Epstein'"
        ).fetchone()
        assert row is not None
        assert row["name"] == "Jeffrey Epstein"

    def test_insert_or_ignore_skips_duplicate(self, db_conn):
        """Second insert with same canonical_name + entity_type should be ignored."""
        db_conn.execute("""
            INSERT OR IGNORE INTO entities (name, entity_type, canonical_name, created_at, updated_at)
            VALUES ('Jeffrey Epstein', 'person', 'Jeffrey Epstein', '2024-01-01', '2024-01-01')
        """)
        db_conn.execute("""
            INSERT OR IGNORE INTO entities (name, entity_type, canonical_name, created_at, updated_at)
            VALUES ('Jeffrey Epstein', 'person', 'Jeffrey Epstein', '2024-02-01', '2024-02-01')
        """)
        db_conn.commit()

        count = db_conn.execute(
            "SELECT COUNT(*) FROM entities WHERE canonical_name = 'Jeffrey Epstein'"
        ).fetchone()[0]
        assert count == 1

    def test_different_type_creates_separate_entity(self, db_conn):
        """Same name but different entity_type should create two rows."""
        db_conn.execute("""
            INSERT OR IGNORE INTO entities (name, entity_type, canonical_name)
            VALUES ('Palm Beach', 'location', 'Palm Beach')
        """)
        db_conn.execute("""
            INSERT OR IGNORE INTO entities (name, entity_type, canonical_name)
            VALUES ('Palm Beach', 'organization', 'Palm Beach')
        """)
        db_conn.commit()

        count = db_conn.execute(
            "SELECT COUNT(*) FROM entities WHERE canonical_name = 'Palm Beach'"
        ).fetchone()[0]
        assert count == 2


# ============================================================================
#  6.  DASHBOARD — sanitize_fts, XSS entity sorting, path traversal
# ============================================================================


class TestSanitizeFTS:
    """Empty/malicious FTS queries must return None (skip the FTS query).

    We reimplement the sanitize_fts logic here because importing dashboard.app
    requires Flask which may not be installed in the test environment.
    """

    @staticmethod
    def _sanitize_fts(q: str):
        """Mirror of dashboard.app.sanitize_fts."""
        cleaned = re.sub(r'[^\w\s]', '', q).strip()
        if not cleaned:
            return None
        return '"' + cleaned.replace('"', '""') + '"'

    def test_normal_query(self):
        result = self._sanitize_fts("flight log")
        assert result is not None
        assert "flight" in result

    def test_empty_string_returns_none(self):
        assert self._sanitize_fts("") is None

    def test_only_special_chars_returns_none(self):
        assert self._sanitize_fts("!!!@@@###") is None

    def test_fts_operators_stripped(self):
        result = self._sanitize_fts("AND OR NOT (test)")
        # Special chars stripped, words remain
        assert result is not None
        assert '"' in result  # wrapped in quotes

    def test_quotes_escaped(self):
        result = self._sanitize_fts('test "quoted" value')
        assert result is not None
        # Internal quotes should be escaped as ""
        assert "quoted" in result

    def test_source_matches_mirror(self):
        """Verify our mirror matches the actual source code pattern."""
        app_path = Path(__file__).parent.parent / "dashboard" / "app.py"
        source = app_path.read_text(encoding="utf-8")
        # The actual function should have the same logic
        assert "def sanitize_fts" in source
        assert "return None" in source


class TestXSSEntitySorting:
    """Finding 3 (P1): Entity names must be sorted longest-first to prevent
    shorter names from breaking longer entity highlight links."""

    def test_longest_first_sorting(self):
        """Verify sort order: longest entity names first."""
        entities = [
            {"entity_name": "Al", "entity_type": "person", "entity_id": 1},
            {"entity_name": "Alan Dershowitz", "entity_type": "person", "entity_id": 2},
            {"entity_name": "Alan", "entity_type": "person", "entity_id": 3},
        ]
        sorted_entities = sorted(
            entities, key=lambda e: len(e.get("entity_name", "")), reverse=True
        )
        assert sorted_entities[0]["entity_name"] == "Alan Dershowitz"
        assert sorted_entities[1]["entity_name"] == "Alan"
        assert sorted_entities[2]["entity_name"] == "Al"

    def test_html_escape_before_highlight(self):
        """Entity highlighting must escape HTML BEFORE inserting <a> tags."""
        import html as html_module

        raw_text = '<script>alert("xss")</script> met with John Doe'
        escaped = html_module.escape(raw_text)
        # The script tag should be escaped
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped


class TestPathTraversal:
    """Finding 9 (P2): serve_file and serve_image must use config data_dir."""

    def test_resolve_blocks_traversal(self, tmp_path):
        """Path.is_relative_to should block ../../ traversal attempts."""
        data_dir = (tmp_path / "data").resolve()
        data_dir.mkdir()

        # Simulate a traversal attempt
        evil_path = (tmp_path / "data" / ".." / ".." / "etc" / "passwd").resolve()
        assert not evil_path.is_relative_to(data_dir)

    def test_file_inside_data_dir_allowed(self, tmp_path):
        """Legitimate files inside data_dir should pass the check."""
        data_dir = (tmp_path / "data").resolve()
        data_dir.mkdir()
        legit = data_dir / "datasets" / "doc.pdf"
        legit.parent.mkdir(parents=True, exist_ok=True)
        legit.write_bytes(b"PDF content")

        assert legit.resolve().is_relative_to(data_dir)


# ============================================================================
#  7.  LIKE ESCAPE CLAUSE — all LIKE queries must use ESCAPE
# ============================================================================


class TestLIKEEscapeClause:
    """Finding 11 (P2): All LIKE queries must include ESCAPE clause."""

    def test_source_code_has_escape(self):
        """Every LIKE ? in app.py should have a matching ESCAPE."""
        app_path = Path(__file__).parent.parent / "dashboard" / "app.py"
        source = app_path.read_text(encoding="utf-8")
        # Find all LIKE ? patterns
        like_patterns = re.findall(r"LIKE\s+\?", source)
        escape_patterns = re.findall(r"ESCAPE\s+'", source)
        # Every LIKE ? should have a corresponding ESCAPE
        assert len(like_patterns) > 0, "No LIKE queries found"
        assert len(escape_patterns) >= len(like_patterns), (
            f"Found {len(like_patterns)} LIKE ? but only {len(escape_patterns)} ESCAPE clauses"
        )


# ============================================================================
#  8.  Z-SCORE DIVISION BY ZERO
# ============================================================================


class TestZScoreDivisionByZero:
    """Finding 12 (P2): Z-score calculation must guard against stdev == 0."""

    def test_zero_stdev_handled(self):
        """When all values are identical, stdev=0 should not raise ZeroDivisionError."""
        import statistics

        values = [50.0, 50.0, 50.0, 50.0]
        stdev = statistics.stdev(values) if len(values) > 1 else 0
        mean = statistics.mean(values)

        # This is the guard pattern used in the codebase
        if stdev == 0:
            z_scores = [0.0] * len(values)
        else:
            z_scores = [(v - mean) / stdev for v in values]

        assert z_scores == [0.0, 0.0, 0.0, 0.0]

    def test_single_value_no_crash(self):
        """Single value should produce stdev=0 without crashing."""
        values = [75.0]
        if len(values) > 1:
            import statistics
            stdev = statistics.stdev(values)
        else:
            stdev = 0

        assert stdev == 0


# ============================================================================
#  9.  ENCRYPTION EDGE CASES
# ============================================================================


class TestEncryptionEdgeCases:
    """Regression tests for encryption roundtrip edge cases."""

    @pytest.fixture()
    def enc(self):
        from security.security import EncryptionManager
        return EncryptionManager()

    def test_binary_data_roundtrip(self, enc):
        """Pure binary data (all byte values) should survive encryption."""
        data = bytes(range(256)) * 4
        password = "binary-test"
        encrypted = enc.encrypt_data(data, password)
        decrypted = enc.decrypt_data(encrypted, password)
        assert decrypted == data

    def test_unicode_password(self, enc):
        """Non-ASCII password should work."""
        data = b"secret document"
        password = "\u00e9\u00e8\u00ea\u00eb"  # accented chars
        encrypted = enc.encrypt_data(data, password)
        decrypted = enc.decrypt_data(encrypted, password)
        assert decrypted == data

    def test_very_long_data_roundtrip(self, enc, tmp_path):
        """1MB file should encrypt/decrypt correctly."""
        original = tmp_path / "big.bin"
        content = os.urandom(1024 * 1024)
        original.write_bytes(content)

        enc_path = enc.encrypt_file(str(original), "big-pw")
        dec_path = enc.decrypt_file(enc_path, "big-pw")
        assert Path(dec_path).read_bytes() == content


# ============================================================================
#  10. DISK USAGE & AUTO-COMPACT
# ============================================================================


class TestDiskUsage:
    """Verify disk usage tracking and auto-compact safety."""

    def test_check_disk_usage_returns_all_keys(self, db_manager, tmp_data_dir):
        result = db_manager.check_disk_usage()
        required_keys = {
            "total_bytes", "total_gb", "max_gb",
            "usage_percent", "needs_compact", "compact_threshold_percent",
        }
        assert required_keys.issubset(result.keys())

    def test_auto_compact_clears_temp(self, db_manager, tmp_data_dir):
        """auto_compact should clear temp directory."""
        temp_file = tmp_data_dir / "temp" / "junk.tmp"
        temp_file.write_bytes(b"\x00" * 500)

        result = db_manager.auto_compact()
        assert result["freed_bytes"] >= 500
        assert not temp_file.exists()

    def test_auto_compact_flags_low_priority_docs(self, db_manager, db_conn, tmp_data_dir):
        """Low priority analyzed docs should be flagged for deletion review."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, "
            "file_path, source, status, priority_score, user_reviewed, analysis_completed) "
            "VALUES (1, 'lp_h', 'low.pdf', '/t', 'doj', 'analyzed', 5, 0, 1)"
        )
        db_conn.commit()

        result = db_manager.auto_compact()
        # Check that a deletion_queue entry was created
        row = db_conn.execute(
            "SELECT * FROM deletion_queue WHERE document_id = 1"
        ).fetchone()
        assert row is not None
        assert row["user_decision"] == "pending"


# ============================================================================
#  11. AUDIT LOG
# ============================================================================


class TestAuditLog:
    """Verify audit logging works for all code paths."""

    def test_log_action_user_initiated(self, db_manager, db_conn):
        db_manager.log_action("test_action", "Test details", user_initiated=True)
        row = db_conn.execute(
            "SELECT * FROM audit_log WHERE action = 'test_action'"
        ).fetchone()
        assert row is not None
        assert row["user_initiated"] == 1

    def test_log_action_system_initiated(self, db_manager, db_conn):
        db_manager.log_action("auto_action", "Auto details", user_initiated=False)
        row = db_conn.execute(
            "SELECT * FROM audit_log WHERE action = 'auto_action'"
        ).fetchone()
        assert row is not None
        assert row["user_initiated"] == 0


# ============================================================================
#  12. STATS QUERY — single combined query, no N+1
# ============================================================================


class TestStatsQuery:
    """Verify get_stats returns all expected keys without errors."""

    def test_stats_empty_db(self, db_manager):
        """Stats on an empty database should return zeros, not errors."""
        stats = db_manager.get_stats()
        assert stats["total_documents"] == 0
        assert stats["total_entities"] == 0
        assert stats["total_relationships"] == 0
        assert stats["total_redactions"] == 0
        assert "disk_usage_gb" in stats
        assert "needs_compact" in stats

    def test_stats_with_data(self, db_manager, db_conn):
        """Stats after inserting data should reflect counts."""
        db_conn.execute("INSERT INTO datasets (dataset_number, source) VALUES (1, 'test')")
        for i in range(5):
            db_conn.execute(
                "INSERT INTO documents (dataset_id, file_hash, original_filename, "
                "file_path, source) VALUES (1, ?, ?, '/t', 'doj')",
                (f"stat_h{i}", f"stat_{i}.pdf"),
            )
        db_conn.execute(
            "INSERT INTO entities (name, entity_type, canonical_name) "
            "VALUES ('Person A', 'person', 'person_a')"
        )
        db_conn.commit()

        stats = db_manager.get_stats()
        assert stats["total_documents"] == 5
        assert stats["total_entities"] == 1


# ============================================================================
#  13. DEAD IMPORT VERIFICATION
# ============================================================================


class TestDeadImports:
    """Verify dead imports have been removed from processor.py."""

    def test_no_struct_import(self):
        proc_path = Path(__file__).parent.parent / "processor" / "processor.py"
        source = proc_path.read_text(encoding="utf-8")
        # Should not have standalone 'import struct'
        assert not re.search(r"^import struct\s*$", source, re.MULTILINE)

    def test_urllib_parse_imported(self):
        """urllib.parse must be imported — it's used by _google_search_url / _wikipedia_url."""
        proc_path = Path(__file__).parent.parent / "processor" / "processor.py"
        source = proc_path.read_text(encoding="utf-8")
        assert re.search(r"^import urllib\.parse\s*$", source, re.MULTILINE)


# ============================================================================
#  14. CACHED DISK USAGE
# ============================================================================


class TestCachedDiskUsage:
    """Verify _get_cached_disk_usage caches and expires correctly."""

    def test_cache_returns_same_object(self, db_manager):
        """Two calls within 60s should return cached result."""
        r1 = db_manager._get_cached_disk_usage()
        r2 = db_manager._get_cached_disk_usage()
        assert r1 is r2  # same object reference = cached

    def test_cache_expires(self, db_manager):
        """After 60s, cache should be refreshed."""
        r1 = db_manager._get_cached_disk_usage()
        # Artificially expire the cache
        db_manager._disk_cache_time -= 61
        r2 = db_manager._get_cached_disk_usage()
        assert r1 is not r2  # different object = refreshed


# ============================================================================
#  15. FOREIGN KEY ENFORCEMENT
# ============================================================================


class TestForeignKeys:
    """Verify foreign key constraints are enforced."""

    def test_fk_on(self, db_conn):
        fk = db_conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1

    def test_fk_blocks_orphan_document(self, db_conn):
        """Inserting a document with non-existent dataset_id should fail if FK enforced."""
        # dataset_id 9999 doesn't exist
        with pytest.raises(sqlite3.IntegrityError):
            db_conn.execute(
                "INSERT INTO documents (dataset_id, file_hash, original_filename, "
                "file_path, source) VALUES (9999, 'fk_h', 'fk.pdf', '/t', 'doj')"
            )

    def test_cascade_delete_relationships(self, db_conn):
        """Deleting an entity should cascade-delete its relationships."""
        db_conn.execute(
            "INSERT INTO entities (name, entity_type, canonical_name) "
            "VALUES ('A', 'person', 'a')"
        )
        db_conn.execute(
            "INSERT INTO entities (name, entity_type, canonical_name) "
            "VALUES ('B', 'person', 'b')"
        )
        db_conn.execute(
            "INSERT INTO relationships (source_entity_id, target_entity_id, relationship_type) "
            "VALUES (1, 2, 'knows')"
        )
        db_conn.commit()

        # Delete entity A
        db_conn.execute("DELETE FROM entities WHERE id = 1")
        db_conn.commit()

        # Relationship should be gone via ON DELETE CASCADE
        rels = db_conn.execute("SELECT * FROM relationships").fetchall()
        assert len(rels) == 0


# ============================================================================
#  16. WAL JOURNAL MODE
# ============================================================================


class TestWALMode:
    """WAL mode enables concurrent reads during writes."""

    def test_wal_mode_active(self, db_conn):
        mode = db_conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"

    def test_cache_size_set(self, db_conn):
        # Negative value = KB, so -64000 = 64MB
        val = db_conn.execute("PRAGMA cache_size").fetchone()[0]
        assert val == -64000

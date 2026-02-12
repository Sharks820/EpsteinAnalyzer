"""
End-to-end integration tests for EpsteinAnalyzer.
Tests module imports, class instantiation, and cross-module interactions.
"""
import sys
import sqlite3
from pathlib import Path

import pytest


class TestModuleImports:
    """Verify all package __init__.py imports resolve without error."""

    def test_import_database(self):
        from database import DatabaseManager
        assert DatabaseManager is not None

    @pytest.mark.skipif(
        not all(__import__("importlib").util.find_spec(m) for m in ["fitz", "pytesseract", "PIL"]),
        reason="Requires PyMuPDF, pytesseract, Pillow",
    )
    def test_import_processor(self):
        from processor import (
            OCREngine, DocumentClassifier, RedactionForensics,
            ImageForensics, EmailChainStitcher, EntityExtractor,
            PriorityScorer, ProcessorEngine,
        )
        assert all(cls is not None for cls in [
            OCREngine, DocumentClassifier, RedactionForensics,
            ImageForensics, EmailChainStitcher, EntityExtractor,
            PriorityScorer, ProcessorEngine,
        ])

    def test_import_security(self):
        from security.security import (
            EncryptionManager, IntegrityMonitor, HoneypotManager,
            SessionWiper, USBProtection, SecurityManager,
        )
        assert EncryptionManager is not None
        assert SecurityManager is not None

    def test_import_ai_pipeline(self):
        from ai_pipeline import (
            PromptBuilder, CodexRunner, GeminiRunner, ClaudeRunner,
            ResponseParser, ConsensusEngine, GracefulDegradation,
            PipelineEngine,
        )
        assert PipelineEngine is not None

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("networkx"),
        reason="Requires networkx",
    )
    def test_import_knowledge_graph(self):
        from knowledge_graph import (
            GraphEngine, EntityResolver, ConnectionMapper,
            PatternDetector, RedactionResolver, TemporalAnalyzer,
            EvidenceScorer, GraphExporter,
        )
        assert GraphEngine is not None

    def test_import_export(self):
        from export import (
            RedditExporter, PublicViewerExporter,
            ImageRedactionExporter, ExportManager,
        )
        assert ExportManager is not None

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("requests"),
        reason="Requires requests",
    )
    def test_import_harvester(self):
        from harvester import HarvesterEngine, DOJScraper
        assert HarvesterEngine is not None


class TestDatabaseToProcessor:
    """Test processor can work with a live database."""

    def test_insert_document_and_page(self, db_conn):
        db_conn.execute(
            "INSERT INTO datasets (dataset_number, source) VALUES (1, 'doj')"
        )
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, file_path, source) "
            "VALUES (1, 'sha256abc', 'test.pdf', '/tmp/test.pdf', 'doj')"
        )
        db_conn.execute(
            "INSERT INTO document_pages (document_id, page_number, text_content, ocr_confidence, has_redactions) "
            "VALUES (1, 1, 'Sample extracted text from page one.', 0.95, 0)"
        )
        db_conn.commit()

        # Query back
        row = db_conn.execute(
            "SELECT * FROM document_pages WHERE document_id = 1 AND page_number = 1"
        ).fetchone()
        assert row is not None
        assert row["text_content"] == "Sample extracted text from page one."
        assert row["ocr_confidence"] == 0.95

    def test_entity_and_relationship(self, db_conn):
        db_conn.execute(
            "INSERT INTO entities (name, entity_type, canonical_name) VALUES (?, ?, ?)",
            ("John Doe", "person", "john_doe"),
        )
        db_conn.execute(
            "INSERT INTO entities (name, entity_type, canonical_name) VALUES (?, ?, ?)",
            ("Acme Corp", "organization", "acme_corp"),
        )
        db_conn.execute(
            "INSERT INTO relationships (source_entity_id, target_entity_id, relationship_type, weight) "
            "VALUES (1, 2, 'employed_by', 3.0)"
        )
        db_conn.commit()

        rels = db_conn.execute(
            "SELECT * FROM relationships WHERE source_entity_id = 1"
        ).fetchall()
        assert len(rels) == 1
        assert rels[0]["relationship_type"] == "employed_by"
        assert rels[0]["weight"] == 3.0

    def test_email_chain_stitching_schema(self, db_conn):
        """Verify email chain + message schema works for stitching."""
        db_conn.execute(
            "INSERT INTO datasets (dataset_number, source) VALUES (2, 'doj')"
        )
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, file_path, source) "
            "VALUES (1, 'emailhash1', 'email1.pdf', '/tmp/email1.pdf', 'doj')"
        )
        db_conn.execute(
            "INSERT INTO email_chains (chain_identifier, normalized_subject, email_count) "
            "VALUES ('chain_abc', 're: meeting', 2)"
        )
        # Insert two messages with positions
        db_conn.execute(
            "INSERT INTO email_messages (chain_id, document_id, position_in_chain, subject, email_date) "
            "VALUES (1, 1, 1, 'RE: Meeting', '2003-06-01')"
        )
        db_conn.execute(
            "INSERT INTO email_messages (chain_id, document_id, position_in_chain, subject, email_date) "
            "VALUES (1, 1, 2, 'RE: Meeting', '2003-06-02')"
        )
        db_conn.commit()

        msgs = db_conn.execute(
            "SELECT * FROM email_messages WHERE chain_id = 1 ORDER BY position_in_chain"
        ).fetchall()
        assert len(msgs) == 2
        assert msgs[0]["position_in_chain"] == 1
        assert msgs[1]["position_in_chain"] == 2

    def test_redaction_forensics_schema(self, db_conn):
        """Verify redaction table supports all recovery methods."""
        db_conn.execute(
            "INSERT INTO datasets (dataset_number, source) VALUES (3, 'doj')"
        )
        db_conn.execute(
            "INSERT INTO documents (dataset_id, file_hash, original_filename, file_path, source) "
            "VALUES (1, 'redhash', 'redacted.pdf', '/tmp/r.pdf', 'doj')"
        )
        methods = [
            "text_layer", "pdf_layer", "metadata", "ocr_mismatch",
            "copy_paste", "font_analysis", "cross_document", "ai_inference",
        ]
        for i, method in enumerate(methods):
            db_conn.execute(
                "INSERT INTO redactions (document_id, page_number, recovery_method, recovered_text, recovery_confidence, is_recovered) "
                "VALUES (1, ?, ?, ?, ?, 1)",
                (i + 1, method, f"recovered via {method}", 0.8),
            )
        db_conn.commit()

        rows = db_conn.execute("SELECT * FROM redactions WHERE document_id = 1").fetchall()
        assert len(rows) == len(methods)

    def test_removed_files_tracking(self, db_conn):
        """Verify removed file tracking — highest priority feature."""
        db_conn.execute(
            "INSERT INTO removed_files (original_url, original_source, removed_detected_at, priority) "
            "VALUES (?, ?, datetime('now'), 'CRITICAL')",
            ("https://justice.gov/epstein/file123.pdf", "doj"),
        )
        db_conn.commit()
        row = db_conn.execute("SELECT * FROM removed_files WHERE priority = 'CRITICAL'").fetchone()
        assert row is not None
        assert row["recovered"] == 0


class TestSecurityIntegration:
    """Test security manager with live database."""

    def test_security_manager_init(self, db_manager, tmp_data_dir):
        from security.security import SecurityManager
        sm = SecurityManager(db_manager, str(tmp_data_dir))
        assert sm.encryption is not None
        assert sm.integrity is not None
        assert sm.honeypots is not None

    def test_initialize_security(self, db_manager, tmp_data_dir):
        from security.security import SecurityManager
        sm = SecurityManager(db_manager, str(tmp_data_dir))
        sm.initialize_security()

        # Verify honeypots were created
        hp_dir = tmp_data_dir / "honeypots"
        assert hp_dir.exists()

        # Verify DB was NOT registered for integrity (our fix)
        conn = db_manager.get_connection()
        try:
            db_file = str(tmp_data_dir / "epstein_analyzer.db")
            row = conn.execute(
                "SELECT * FROM file_integrity WHERE file_path = ?", (db_file,)
            ).fetchone()
            assert row is None, "DB file should NOT be registered for integrity monitoring"
        finally:
            conn.close()

    def test_backup_and_restore(self, db_manager, tmp_data_dir, tmp_path):
        from security.security import SecurityManager
        sm = SecurityManager(db_manager, str(tmp_data_dir))

        # Create test files
        test_file = tmp_data_dir / "datasets" / "important.pdf"
        test_file.write_bytes(b"important evidence data " * 100)

        # Backup via BackupManager
        backup_dir = tmp_path / "test_backup"
        result = sm.backup.create_backup(str(backup_dir), "backup-password-123")
        assert result["files_backed_up"] > 0

        # Restore to different location
        restore_dir = tmp_path / "restored"
        restore_dir.mkdir()
        result = sm.backup.restore_backup(str(backup_dir), "backup-password-123", str(restore_dir))
        assert result["files_restored"] > 0


class TestSetup:
    """Test setup.py functions."""

    def test_check_prerequisites(self, project_root):
        sys.path.insert(0, str(project_root))
        from setup import check_prerequisites

        results = check_prerequisites()
        assert "python" in results
        assert results["python"]["installed"] is True
        assert "git" in results

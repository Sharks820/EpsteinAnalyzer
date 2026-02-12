"""
Shared fixtures for EpsteinAnalyzer test suite.
"""
import os
import sys
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest
import yaml

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="session")
def project_root():
    return PROJECT_ROOT


@pytest.fixture()
def tmp_data_dir(tmp_path):
    """Create a temporary data directory mimicking the real layout."""
    data_dir = tmp_path / "data"
    for sub in ("datasets", "analysis_queue", "findings", "backups", "temp", "honeypots"):
        (data_dir / sub).mkdir(parents=True)
    return data_dir


@pytest.fixture()
def test_config(tmp_data_dir, tmp_path):
    """Write a minimal settings.yaml and return its path."""
    cfg = {
        "project": {
            "name": "EpsteinAnalyzer-Test",
            "version": "1.0.0",
            "data_dir": str(tmp_data_dir),
            "max_disk_gb": 1,
            "auto_compact_threshold": 0.78,
        },
        "dashboard": {
            "host": "127.0.0.1",
            "port": 0,  # random port
            "debug": False,
            "secret_key": "test-secret-key-not-for-prod",
        },
        "harvester": {"enabled_sources": []},
        "processor": {
            "ocr": {
                "engine": "tesseract",
                "languages": ["eng"],
                "dpi": 300,
                "preprocessing": True,
            },
            "redaction_forensics": {
                "text_layer_extraction": True,
                "pdf_layer_analysis": True,
                "metadata_extraction": True,
                "ocr_layer_mismatch": True,
                "copy_paste_extraction": True,
                "font_character_analysis": True,
                "cross_document_matching": True,
                "ai_inference": False,
            },
            "image_forensics": {
                "auto_quarantine_minors": True,
                "require_user_approval": True,
            },
            "email_chain": {
                "subject_normalization": True,
                "participant_matching": True,
                "quoted_text_detection": True,
                "gap_detection": True,
                "auto_restitch_on_new": True,
            },
            "priority_scoring": {
                "high_value_names_weight": 30,
                "redaction_weight": 20,
                "email_attachment_weight": 15,
                "financial_weight": 15,
                "location_weight": 10,
                "case_reference_weight": 10,
                "codeword_weight": 25,
                "removed_file_weight": 50,
                "priority_threshold": 60,
            },
        },
        "ai_pipeline": {
            "models": {
                "codex": {"enabled": False, "cli_command": "codex", "timeout_seconds": 10},
                "gemini": {"enabled": False, "cli_command": "gemini", "timeout_seconds": 10},
                "claude": {"enabled": False, "cli_command": "claude", "timeout_seconds": 10},
            },
            "consensus": {
                "min_models_for_consensus": 2,
                "agreement_threshold": 0.7,
                "backfill_when_model_returns": True,
            },
            "batch": {"max_batch_size": 5, "chain_aware": True, "rate_limit_seconds": 0},
        },
        "knowledge_graph": {
            "entity_types": ["person", "organization", "location"],
            "auto_inference": {"co_occurrence": True, "transitive_connections": True,
                               "temporal_clustering": False, "pattern_detection": False},
            "redaction_resolution": {"track_candidates": True, "re_evaluate_on_new_data": True,
                                     "min_confidence_for_suggestion": 0.3},
        },
        "security": {
            "encryption": {"algorithm": "AES-256-GCM", "key_derivation": "argon2id"},
            "integrity": {"check_on_startup": True, "hash_algorithm": "sha256"},
            "honeypots": {"enabled": True, "file_count": 2},
            "session": {"wipe_temp_on_exit": True, "clear_clipboard": False},
            "backup": {"prompt_after_session": False, "incremental": True, "encrypt_backups": True},
        },
        "evidence": {
            "scoring": {
                "direct_admission": 40,
                "financial_link": 35,
                "flight_log": 30,
                "eyewitness_testimony": 30,
                "photo_video": 25,
                "email_coordination": 20,
                "victim_deposition": 20,
                "redaction_concealment": 15,
                "convicted_associate": 10,
                "general_cooccurrence": 5,
            }
        },
        "export": {
            "reddit": {"strip_victim_names": True, "require_review": True, "auto_archive_wayback": False},
            "public_viewer": {"min_score_for_inclusion": 50, "exclude_ai_inferences": True, "strip_raw_text": True},
        },
    }
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "settings.yaml"
    with open(config_path, "w") as f:
        yaml.dump(cfg, f)
    return str(config_path)


@pytest.fixture()
def db_manager(test_config):
    """Create and initialize a DatabaseManager with temp config."""
    from database.db import DatabaseManager

    db = DatabaseManager(config_path=test_config)
    db.initialize()
    return db


@pytest.fixture()
def db_conn(db_manager):
    """Provide a database connection that auto-closes."""
    conn = db_manager.get_connection()
    yield conn
    conn.close()

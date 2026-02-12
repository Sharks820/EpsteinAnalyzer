"""
Tests for the security module — encryption, integrity, honeypots.
"""
import os
import hashlib
from pathlib import Path

import pytest


class TestEncryptionManager:
    """Test AES-256-GCM encryption round-trips."""

    @pytest.fixture()
    def enc(self):
        from security.security import EncryptionManager
        return EncryptionManager()

    def test_encrypt_decrypt_data_roundtrip(self, enc):
        plaintext = b"Confidential document content here."
        password = "strong-test-password-42"
        encrypted = enc.encrypt_data(plaintext, password)
        assert encrypted != plaintext
        decrypted = enc.decrypt_data(encrypted, password)
        assert decrypted == plaintext

    def test_wrong_password_fails(self, enc):
        from cryptography.exceptions import InvalidTag
        plaintext = b"secret"
        encrypted = enc.encrypt_data(plaintext, "correct")
        with pytest.raises(InvalidTag):
            enc.decrypt_data(encrypted, "wrong")

    def test_encrypt_decrypt_file_roundtrip(self, enc, tmp_path):
        original = tmp_path / "doc.pdf"
        content = os.urandom(256)
        original.write_bytes(content)

        password = "file-test-pw"
        enc_path = enc.encrypt_file(str(original), password)
        assert enc_path.endswith(".enc")
        assert Path(enc_path).exists()

        # Decrypt
        dec_path = enc.decrypt_file(enc_path, password)
        assert Path(dec_path).exists()
        assert Path(dec_path).read_bytes() == content

    def test_chunked_large_file(self, enc, tmp_path):
        """Verify chunked encrypt/decrypt works for files larger than CHUNK_SIZE."""
        original = tmp_path / "large.bin"
        # Create file larger than 64KB chunk size
        content = os.urandom(200_000)
        original.write_bytes(content)

        password = "chunked-pw"
        enc_path = enc.encrypt_file(str(original), password)
        dec_path = enc.decrypt_file(enc_path, password)
        assert Path(dec_path).read_bytes() == content

    def test_decrypt_output_path_suffix_strip(self, enc, tmp_path):
        """Verify .enc suffix is properly stripped (not brittle .replace)."""
        original = tmp_path / "report.enc.pdf"
        original.write_bytes(b"data")
        enc_path = enc.encrypt_file(str(original), "pw")
        # encrypted file should be report.enc.pdf.enc
        assert enc_path.endswith(".enc.pdf.enc")
        dec_path = enc.decrypt_file(enc_path, "pw")
        # Should strip only the trailing .enc, preserving the .enc in the middle
        assert dec_path.endswith(".enc.pdf")

    def test_empty_file_roundtrip(self, enc, tmp_path):
        original = tmp_path / "empty.txt"
        original.write_bytes(b"")
        enc_path = enc.encrypt_file(str(original), "pw")
        dec_path = enc.decrypt_file(enc_path, "pw")
        assert Path(dec_path).read_bytes() == b""


class TestIntegrityMonitor:
    """Test file integrity monitoring."""

    @pytest.fixture()
    def monitor(self, db_manager):
        from security.security import IntegrityMonitor
        return IntegrityMonitor(db_manager)

    def test_register_and_verify(self, monitor, tmp_data_dir):
        test_file = tmp_data_dir / "test_integrity.txt"
        test_file.write_text("integrity check content")
        monitor.register_file(str(test_file))
        results = monitor.verify_all()
        assert results["verified"] == 1
        assert results["tampered"] == []

    def test_tamper_detection(self, monitor, tmp_data_dir):
        test_file = tmp_data_dir / "tamper_me.txt"
        test_file.write_text("original content")
        monitor.register_file(str(test_file))

        # Tamper with the file
        test_file.write_text("MODIFIED CONTENT!")
        results = monitor.verify_all()
        assert len(results["tampered"]) == 1
        assert results["tampered"][0]["path"] == str(test_file)

    def test_missing_file_detection(self, monitor, tmp_data_dir):
        test_file = tmp_data_dir / "will_delete.txt"
        test_file.write_text("ephemeral")
        monitor.register_file(str(test_file))
        test_file.unlink()
        results = monitor.verify_all()
        assert len(results["missing"]) == 1

    def test_single_connection_for_verify(self, monitor, tmp_data_dir):
        """Verify that verify_all uses a single DB transaction (not per-file)."""
        for i in range(5):
            f = tmp_data_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")
            monitor.register_file(str(f))
        # If this doesn't raise "database is locked", the fix works
        results = monitor.verify_all()
        assert results["verified"] == 5


class TestHoneypotManager:
    @pytest.fixture()
    def honeypots(self, db_manager, tmp_data_dir):
        from security.security import HoneypotManager
        return HoneypotManager(db_manager, str(tmp_data_dir))

    def test_create_honeypots(self, honeypots, tmp_data_dir):
        honeypots.create_honeypots()
        # Honeypots are hidden in the findings directory
        findings_dir = tmp_data_dir / "findings"
        created = list(findings_dir.iterdir())
        assert len(created) > 0


class TestUSBProtection:
    @pytest.fixture()
    def usb(self, tmp_path):
        from security.security import USBProtection
        return USBProtection(str(tmp_path / "backup"))

    def test_successful_attempt_resets(self, usb):
        usb.backup_path.mkdir(parents=True, exist_ok=True)
        result = usb.record_attempt(success=False)
        assert result is True  # under threshold
        result = usb.record_attempt(success=True)
        assert result is True
        # Counter should be reset
        assert usb._get_attempts() == 0

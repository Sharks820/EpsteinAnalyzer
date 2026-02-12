"""
Tests for processor utilities — LIKE escaping, extension sanitization, regex patterns.
"""
import re
import sqlite3

import pytest


class TestLIKEEscaping:
    """Verify LIKE wildcard characters are properly escaped."""

    def test_percent_escaped(self):
        """Ensure % in search text doesn't act as wildcard."""
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (val TEXT)")
        conn.execute("INSERT INTO t VALUES ('100% complete')")
        conn.execute("INSERT INTO t VALUES ('other text here')")
        conn.commit()

        # Escaped: search for literal "100%"
        search = "100%"
        safe = search.replace("%", r"\%").replace("_", r"\_")
        rows = conn.execute(
            r"SELECT val FROM t WHERE val LIKE ? ESCAPE '\'", (f"%{safe}%",)
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "100% complete"

    def test_underscore_escaped(self):
        """Ensure _ in search text doesn't act as single-char wildcard."""
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (val TEXT)")
        conn.execute("INSERT INTO t VALUES ('file_name.pdf')")
        conn.execute("INSERT INTO t VALUES ('filename.pdf')")
        conn.commit()

        search = "file_name"
        safe = search.replace("%", r"\%").replace("_", r"\_")
        rows = conn.execute(
            r"SELECT val FROM t WHERE val LIKE ? ESCAPE '\'", (f"%{safe}%",)
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "file_name.pdf"


class TestImageExtSanitization:
    """Verify image extension whitelist prevents path traversal."""

    ALLOWED = {"png", "jpg", "jpeg", "gif", "bmp", "tiff", "tif", "webp"}

    def _sanitize(self, raw_ext):
        img_ext = raw_ext.lower().strip(".") if raw_ext else "png"
        if img_ext not in self.ALLOWED:
            img_ext = "png"
        return img_ext

    def test_normal_extension(self):
        assert self._sanitize("png") == "png"
        assert self._sanitize("jpg") == "jpg"
        assert self._sanitize("TIFF") == "tiff"

    def test_path_traversal_blocked(self):
        assert self._sanitize("../../../etc/passwd") == "png"
        assert self._sanitize("exe") == "png"
        assert self._sanitize("php") == "png"

    def test_dotted_extension(self):
        assert self._sanitize(".jpeg") == "jpeg"

    def test_none_extension(self):
        assert self._sanitize(None) == "png"

    def test_empty_extension(self):
        assert self._sanitize("") == "png"


class TestPDFTextRegex:
    """Verify improved regex for PDF text extraction handles edge cases."""

    # The improved regex that handles escaped parentheses
    TJ_PATTERN = re.compile(r"\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*Tj")
    TJ_ARRAY_PAREN = re.compile(r"\(([^)\\]*(?:\\.[^)\\]*)*)\)")
    TJ_ARRAY_HEX = re.compile(r"<([0-9A-Fa-f]+)>")

    def test_simple_text(self):
        content = "(Hello World) Tj"
        matches = self.TJ_PATTERN.findall(content)
        assert matches == ["Hello World"]

    def test_escaped_parens(self):
        content = r"(Hello \(World\)) Tj"
        matches = self.TJ_PATTERN.findall(content)
        assert len(matches) == 1
        assert r"\(World\)" in matches[0]

    def test_hex_string_extraction(self):
        content = "[<48656C6C6F>] TJ"
        hex_parts = self.TJ_ARRAY_HEX.findall(content)
        assert len(hex_parts) == 1
        decoded = bytes.fromhex(hex_parts[0]).decode("latin-1")
        assert decoded == "Hello"

    def test_mixed_tj_array(self):
        content = "[(Regular text) -10 <576F726C64>] TJ"
        paren = self.TJ_ARRAY_PAREN.findall(content)
        hex_parts = self.TJ_ARRAY_HEX.findall(content)
        assert "Regular text" in paren
        assert bytes.fromhex(hex_parts[0]).decode("latin-1") == "World"


class TestRecoveryLogRedaction:
    """Verify recovered text is not logged at info level."""

    def test_log_message_format(self):
        """Recovery logs should use char count, not actual text."""
        # This is a structural test — verify the format string pattern
        import ast
        import inspect
        from pathlib import Path

        proc_path = Path(__file__).parent.parent / "processor" / "processor.py"
        source = proc_path.read_text(encoding="utf-8")
        # Should NOT contain log.info("Step N recovery: '%s'"
        assert 'log.info("Step 1 recovery:' not in source
        assert 'log.info("Step 2 recovery:' not in source
        assert 'log.info("Step 3 recovery:' not in source
        assert 'log.info("Step 7 recovery:' not in source
        # Should contain log.debug with char count (not actual recovered text)
        assert 'log.debug("Step 1 recovery: [%d chars]' in source
        assert 'log.debug("Step 2 recovery: [%d chars]' in source

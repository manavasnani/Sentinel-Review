"""Tests for language detection helper."""

from pathlib import Path

import pytest

from sentinel.diff.language_detection import (
    detect_language,
    is_supported,
    supported_extensions,
)
from sentinel.models import Language


class TestDetectLanguage:
    def test_python_file(self):
        assert detect_language("app.py") == Language.PYTHON

    def test_javascript_file(self):
        assert detect_language("app.js") == Language.JAVASCRIPT

    def test_typescript_file(self):
        assert detect_language("app.ts") == Language.TYPESCRIPT

    def test_jsx_file(self):
        assert detect_language("Button.jsx") == Language.JAVASCRIPT

    def test_tsx_file(self):
        assert detect_language("Button.tsx") == Language.TYPESCRIPT

    def test_mjs_and_cjs_files(self):
        assert detect_language("module.mjs") == Language.JAVASCRIPT
        assert detect_language("module.cjs") == Language.JAVASCRIPT

    def test_unsupported_extension_returns_none(self):
        assert detect_language("README.md") is None
        assert detect_language("data.json") is None
        assert detect_language("config.yaml") is None

    def test_no_extension_returns_none(self):
        assert detect_language("Dockerfile") is None
        assert detect_language("Makefile") is None

    def test_case_insensitive(self):
        assert detect_language("app.PY") == Language.PYTHON
        assert detect_language("app.Js") == Language.JAVASCRIPT
        assert detect_language("app.TSX") == Language.TYPESCRIPT

    def test_accepts_path_object(self):
        path = Path("src") / "app" / "auth.py"
        assert detect_language(path) == Language.PYTHON

    def test_accepts_full_path_string(self):
        assert detect_language("src/app/auth.py") == Language.PYTHON
        assert detect_language("C:\\Users\\test\\app.py") == Language.PYTHON

    def test_multiple_dots_uses_last_extension(self):
        """A file like 'app.min.js' should be detected as JavaScript."""
        assert detect_language("app.min.js") == Language.JAVASCRIPT
        assert detect_language("test.spec.ts") == Language.TYPESCRIPT


class TestIsSupported:
    def test_supported_file(self):
        assert is_supported("app.py") is True
        assert is_supported("app.js") is True

    def test_unsupported_file(self):
        assert is_supported("README.md") is False
        assert is_supported("data.json") is False


class TestSupportedExtensions:
    def test_returns_set_of_extensions(self):
        exts = supported_extensions()
        assert ".py" in exts
        assert ".js" in exts
        assert ".ts" in exts
        assert ".tsx" in exts
        assert ".jsx" in exts

    def test_all_extensions_start_with_dot(self):
        for ext in supported_extensions():
            assert ext.startswith(".")

    def test_all_extensions_are_lowercase(self):
        for ext in supported_extensions():
            assert ext == ext.lower()

    def test_matches_language_enum(self):
        """Every extension in the set should map to a Language."""
        for ext in supported_extensions():
            assert detect_language(f"test{ext}") is not None
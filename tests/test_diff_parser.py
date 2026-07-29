"""Tests for the diff parser."""

from pathlib import Path

import pytest

from sentinel.diff.parser import parse_diff
from sentinel.exceptions import AnalysisError
from sentinel.models import DiffFile, Language


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "diffs"


def _load_fixture(name: str) -> str:
    """Load a diff fixture from the fixtures directory."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


class TestParseDiffBasics:
    def test_empty_string_returns_empty_list(self):
        assert parse_diff("") == []

    def test_whitespace_only_returns_empty_list(self):
        assert parse_diff("   \n\n   ") == []

    def test_malformed_diff_returns_empty_list(self):
        """
        Garbage input that doesn't look like a valid diff should return an
        empty list rather than crashing. unidiff is permissive and treats
        unparseable input as 'no files changed', which propagates through
        our parser cleanly.
        """
        result = parse_diff("@@ this is broken @@")
        assert result == []

    def test_random_garbage_returns_empty_list(self):
        result = parse_diff("hello world this is not a diff")
        assert result == []


class TestSingleFileAddition:
    def test_parses_new_file(self):
        diff = _load_fixture("single_file_addition.diff")
        results = parse_diff(diff)

        assert len(results) == 1
        df = results[0]
        assert df.file_path == "src/app/auth.py"
        assert df.language == Language.PYTHON
        assert df.is_new_file is True

    def test_new_file_has_all_lines_as_changed(self):
        diff = _load_fixture("single_file_addition.diff")
        results = parse_diff(diff)
        df = results[0]

        # For a new file, all 10 lines should be in the changed range
        assert df.total_changed_lines == 10
        assert df.changed_line_ranges == [(1, 10)]

    def test_new_file_content_includes_vulnerable_code(self):
        diff = _load_fixture("single_file_addition.diff")
        results = parse_diff(diff)
        df = results[0]

        assert "hashlib.md5" in df.new_content
        assert "DEFAULT_PASSWORD" in df.new_content


class TestSingleFileModification:
    def test_parses_modification(self):
        diff = _load_fixture("single_file_modification.diff")
        results = parse_diff(diff)

        assert len(results) == 1
        df = results[0]
        assert df.file_path == "src/app/queries.py"
        assert df.language == Language.PYTHON
        assert df.is_new_file is False

    def test_modification_captures_changed_line(self):
        diff = _load_fixture("single_file_modification.diff")
        results = parse_diff(diff)
        df = results[0]

        # Line 13 was modified (the parameterized query line)
        assert df.contains_line(13)
        assert df.total_changed_lines == 1


class TestMultiFileChange:
    def test_multiple_files_parsed(self):
        diff = _load_fixture("multi_file_change.diff")
        results = parse_diff(diff)

        assert len(results) == 2
        paths = {df.file_path for df in results}
        assert paths == {"src/app/routes.py", "src/utils.py"}

    def test_each_file_has_own_changed_ranges(self):
        diff = _load_fixture("multi_file_change.diff")
        results = parse_diff(diff)

        for df in results:
            assert df.language == Language.PYTHON
            assert df.total_changed_lines > 0


class TestMixedLanguage:
    def test_python_and_js_included(self):
        diff = _load_fixture("mixed_language.diff")
        results = parse_diff(diff)

        # 3 files in diff: .py, .js, .md
        # .md should be filtered out
        assert len(results) == 2

        languages = {df.language for df in results}
        assert languages == {Language.PYTHON, Language.JAVASCRIPT}

    def test_markdown_file_skipped(self):
        diff = _load_fixture("mixed_language.diff")
        results = parse_diff(diff)

        paths = {df.file_path for df in results}
        assert "README.md" not in paths


class TestDeletionOnly:
    def test_deleted_file_skipped(self):
        diff = _load_fixture("deletion_only.diff")
        results = parse_diff(diff)

        # Deleted files have nothing to review
        assert len(results) == 0


class TestPathHandling:
    def test_git_prefix_stripped(self):
        """File paths should not include the 'a/' or 'b/' git prefix."""
        diff = _load_fixture("single_file_modification.diff")
        results = parse_diff(diff)

        assert results[0].file_path == "src/app/queries.py"
        assert not results[0].file_path.startswith("a/")
        assert not results[0].file_path.startswith("b/")


class TestLanguageDetection:
    def test_python_language_assigned(self):
        diff = _load_fixture("single_file_addition.diff")
        results = parse_diff(diff)
        assert results[0].language == Language.PYTHON

    def test_javascript_language_assigned(self):
        diff = _load_fixture("mixed_language.diff")
        results = parse_diff(diff)
        js_file = next(df for df in results if df.file_path.endswith(".js"))
        assert js_file.language == Language.JAVASCRIPT
        

class TestBinaryFile:
    def test_binary_file_skipped(self):
        """Binary files (e.g., images) should not appear in the results."""
        diff = _load_fixture("binary_file.diff")
        results = parse_diff(diff)

        # 2 files in diff: one binary (.png), one Python
        # Only the Python file should come through
        assert len(results) == 1
        assert results[0].file_path == "src/utils.py"

    def test_binary_file_not_in_results(self):
        diff = _load_fixture("binary_file.diff")
        results = parse_diff(diff)

        paths = {df.file_path for df in results}
        assert "assets/logo.png" not in paths
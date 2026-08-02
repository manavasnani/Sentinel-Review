"""Tests for diff-mode analyzer functionality."""

from unittest.mock import MagicMock, patch

import pytest

from sentinel.analyzer import _add_change_markers, analyze_diff_file
from sentinel.models import Confidence, DiffFile, Finding, Language, Severity


class TestAddChangeMarkers:
    """Tests for the internal marker helper — no API calls needed."""

    def test_all_lines_marked_context_when_no_changes(self):
        content = "line 1\nline 2\nline 3"
        result = _add_change_markers(content, [])
        assert "[CONTEXT] line 1" in result
        assert "[CONTEXT] line 2" in result
        assert "[CHANGED]" not in result

    def test_all_lines_marked_changed_when_full_range(self):
        content = "line 1\nline 2\nline 3"
        result = _add_change_markers(content, [(1, 3)])
        assert "[CHANGED] line 1" in result
        assert "[CHANGED] line 2" in result
        assert "[CHANGED] line 3" in result
        assert "[CONTEXT]" not in result

    def test_mixed_markers(self):
        content = "line 1\nline 2\nline 3\nline 4\nline 5"
        result = _add_change_markers(content, [(2, 3)])
        lines = result.split("\n")
        assert "[CONTEXT] line 1" in lines[0]
        assert "[CHANGED] line 2" in lines[1]
        assert "[CHANGED] line 3" in lines[2]
        assert "[CONTEXT] line 4" in lines[3]
        assert "[CONTEXT] line 5" in lines[4]

    def test_multiple_ranges(self):
        content = "\n".join(f"line {i}" for i in range(1, 11))
        result = _add_change_markers(content, [(2, 3), (7, 8)])
        # Lines 2, 3, 7, 8 should be [CHANGED]
        # Lines 1, 4, 5, 6, 9, 10 should be [CONTEXT]
        assert result.count("[CHANGED]") == 4
        assert result.count("[CONTEXT]") == 6

    def test_line_numbers_preserved(self):
        content = "\n".join(f"line {i}" for i in range(1, 11))
        result = _add_change_markers(content, [(5, 5)])
        # Line 5 should have "5" as its number and be marked CHANGED
        assert " 5  [CHANGED]" in result

    def test_empty_content(self):
        assert _add_change_markers("", [(1, 1)]) == ""


class TestAnalyzeDiffFile:
    """Tests for analyze_diff_file with mocked API responses."""

    def _make_diff_file(self, is_new: bool = False) -> DiffFile:
        return DiffFile(
            file_path="src/app/auth.py",
            new_content="import hashlib\n\ndef hash_pw(pw):\n    return hashlib.md5(pw).hexdigest()\n",
            changed_line_ranges=[(3, 4)],
            is_new_file=is_new,
            language=Language.PYTHON,
        )

    @patch("sentinel.analyzer._call_api_and_parse")
    def test_diff_mode_uses_python_prompt_for_python_file(self, mock_call):
        mock_call.return_value = MagicMock(
            findings=[],
            model_copy=MagicMock(return_value=MagicMock()),
        )
        df = self._make_diff_file()
        analyze_diff_file(df)

        # Check that _call_api_and_parse was called with the Python system prompt
        call_args = mock_call.call_args
        system_prompt = call_args.kwargs["system_prompt"]
        assert "senior application security engineer" in system_prompt
        assert "Pull request review mode" in system_prompt  # addendum was appended

    @patch("sentinel.analyzer._call_api_and_parse")
    def test_diff_mode_marks_changed_lines(self, mock_call):
        mock_call.return_value = MagicMock(
            findings=[],
            model_copy=MagicMock(return_value=MagicMock()),
        )
        df = self._make_diff_file()
        analyze_diff_file(df)

        user_message = mock_call.call_args.kwargs["user_message"]
        assert "[CHANGED]" in user_message
        assert "[CONTEXT]" in user_message

    @patch("sentinel.analyzer._call_api_and_parse")
    def test_new_file_mode_omits_markers(self, mock_call):
        mock_call.return_value = MagicMock(
            findings=[],
            model_copy=MagicMock(return_value=MagicMock()),
        )
        df = self._make_diff_file(is_new=True)
        analyze_diff_file(df)

        user_message = mock_call.call_args.kwargs["user_message"]
        assert "NEW file" in user_message
        assert "[CHANGED]" not in user_message  # markers omitted for new files

    @patch("sentinel.analyzer._call_api_and_parse")
    def test_language_tagged_on_result(self, mock_call):
        result_mock = MagicMock()
        result_mock.model_copy.return_value = "result with language"
        mock_call.return_value = result_mock

        df = self._make_diff_file()
        result = analyze_diff_file(df)

        # Verify model_copy was called with language update
        result_mock.model_copy.assert_called_once()
        update_kwarg = result_mock.model_copy.call_args.kwargs["update"]
        assert update_kwarg == {"language": Language.PYTHON}
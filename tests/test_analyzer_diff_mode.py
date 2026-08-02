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
        
class TestAnalyzeDiffFileWithMockedResponse:
    """
    Higher-fidelity tests that mock the Anthropic API response but let
    analyze_diff_file's own logic run end-to-end. Verifies the final
    ReviewResult is constructed correctly.
    """

    def _make_diff_file(
        self, is_new: bool = False, language: Language = Language.PYTHON
    ) -> DiffFile:
        return DiffFile(
            file_path="src/app/auth.py",
            new_content=(
                "import hashlib\n"
                "\n"
                "def hash_password(password):\n"
                "    return hashlib.md5(password.encode()).hexdigest()\n"
            ),
            changed_line_ranges=[(3, 4)],
            is_new_file=is_new,
            language=language,
        )

    def _make_mock_api_response(self, findings: list[dict]) -> MagicMock:
        """Build a mock Anthropic response containing a tool_use block."""
        tool_use_block = MagicMock()
        tool_use_block.type = "tool_use"
        tool_use_block.input = {
            "findings": findings,
            "summary": f"Found {len(findings)} issue(s).",
        }

        usage = MagicMock()
        usage.input_tokens = 5000
        usage.output_tokens = 800

        response = MagicMock()
        response.content = [tool_use_block]
        response.usage = usage
        return response

    @patch("sentinel.analyzer._call_api_with_retry")
    @patch("sentinel.analyzer._build_client")
    def test_returns_review_result_with_findings(self, mock_client, mock_api):
        """End-to-end: mock API response -> parsed ReviewResult."""
        mock_api.return_value = self._make_mock_api_response(
            findings=[
                {
                    "severity": "high",
                    "cwe_id": "CWE-916",
                    "owasp_category": "A02:2021 - Cryptographic Failures",
                    "title": "MD5 used for password hashing",
                    "file_path": "src/app/auth.py",
                    "line_start": 4,
                    "line_end": 4,
                    "description": "MD5 is not a password KDF.",
                    "vulnerable_code": "hashlib.md5(password.encode()).hexdigest()",
                    "suggested_fix": "Use bcrypt or argon2 instead.",
                    "confidence": "high",
                    "reasoning": "MD5 is fast, enabling offline brute-force.",
                }
            ]
        )

        df = self._make_diff_file()
        result = analyze_diff_file(df)

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.cwe_id == "CWE-916"

    @patch("sentinel.analyzer._call_api_with_retry")
    @patch("sentinel.analyzer._build_client")
    def test_result_tagged_with_language(self, mock_client, mock_api):
        mock_api.return_value = self._make_mock_api_response(findings=[])

        df = self._make_diff_file(language=Language.PYTHON)
        result = analyze_diff_file(df)

        assert result.language == Language.PYTHON

    @patch("sentinel.analyzer._call_api_with_retry")
    @patch("sentinel.analyzer._build_client")
    def test_empty_findings_yields_empty_result(self, mock_client, mock_api):
        mock_api.return_value = self._make_mock_api_response(findings=[])

        df = self._make_diff_file()
        result = analyze_diff_file(df)

        assert len(result.findings) == 0
        assert result.finding_count == 0
        assert result.has_findings is False

    @patch("sentinel.analyzer._call_api_with_retry")
    @patch("sentinel.analyzer._build_client")
    def test_token_usage_captured(self, mock_client, mock_api):
        mock_api.return_value = self._make_mock_api_response(findings=[])

        df = self._make_diff_file()
        result = analyze_diff_file(df)

        assert result.input_tokens == 5000
        assert result.output_tokens == 800

    @patch("sentinel.analyzer._call_api_with_retry")
    @patch("sentinel.analyzer._build_client")
    def test_malformed_finding_skipped_not_crashed(self, mock_client, mock_api):
        """A single bad finding should be skipped, others preserved."""
        mock_api.return_value = self._make_mock_api_response(
            findings=[
                {
                    # Good finding
                    "severity": "high",
                    "cwe_id": "CWE-89",
                    "owasp_category": "A03:2021 - Injection",
                    "title": "SQL Injection",
                    "file_path": "src/app/auth.py",
                    "line_start": 4,
                    "line_end": 4,
                    "description": "SQLi.",
                    "vulnerable_code": "query = f'SELECT * FROM u WHERE id = {uid}'",
                    "suggested_fix": "Use parameterized queries.",
                    "confidence": "high",
                    "reasoning": "User input flows to SQL.",
                },
                {
                    # Malformed finding — cwe_id doesn't match the CWE-XX pattern
                    "severity": "high",
                    "cwe_id": "not-a-cwe",
                    "owasp_category": "A03:2021 - Injection",
                    "title": "Bogus",
                    "file_path": "src/app/auth.py",
                    "line_start": 4,
                    "line_end": 4,
                    "description": "x",
                    "vulnerable_code": "x",
                    "suggested_fix": "x",
                    "confidence": "high",
                    "reasoning": "x",
                },
            ]
        )

        df = self._make_diff_file()
        result = analyze_diff_file(df)

        # 1 good finding preserved, 1 malformed silently dropped
        assert len(result.findings) == 1
        assert result.findings[0].cwe_id == "CWE-89"
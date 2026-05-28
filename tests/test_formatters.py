"""Tests for the output formatters."""

import json
from io import StringIO

import pytest
from rich.console import Console

from sentinel.formatters import render_pretty, to_dict, to_json
from sentinel.models import Confidence, Finding, ReviewResult, Severity


def _make_finding(**overrides) -> Finding:
    base = dict(
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
        title="SQL Injection in login",
        file_path="app/auth.py",
        line_start=42,
        line_end=45,
        description="User input concatenated into SQL.",
        vulnerable_code='query = f"SELECT * FROM users WHERE id = {uid}"',
        suggested_fix="Use parameterized queries.",
        confidence=Confidence.HIGH,
        reasoning="uid is request-controlled and unsanitized.",
    )
    base.update(overrides)
    return Finding(**base)


def _make_result(findings=None) -> ReviewResult:
    return ReviewResult(
        findings=findings or [],
        files_analyzed=["app/auth.py"],
        summary="Test review",
        model="claude-sonnet-4-6",
        input_tokens=1000,
        output_tokens=200,
        elapsed_seconds=2.5,
    )


class TestToJson:
    def test_serializes_empty_result(self):
        result = _make_result()
        output = to_json(result)
        parsed = json.loads(output)
        assert parsed["findings"] == []
        assert parsed["model"] == "claude-sonnet-4-6"

    def test_serializes_findings(self):
        result = _make_result(findings=[_make_finding()])
        parsed = json.loads(to_json(result))
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["cwe_id"] == "CWE-89"
        assert parsed["findings"][0]["severity"] == "high"

    def test_indent_zero_produces_compact(self):
        result = _make_result()
        output = to_json(result, indent=0)
        # No leading whitespace on lines after the first
        assert "\n " not in output


class TestToDict:
    def test_returns_dict(self):
        result = _make_result(findings=[_make_finding()])
        d = to_dict(result)
        assert isinstance(d, dict)
        assert d["findings"][0]["severity"] == "high"


class TestRenderPretty:
    def _capture(self, result):
        """Render to an in-memory console and return the captured text."""
        buffer = StringIO()
        console = Console(file=buffer, force_terminal=False, width=120)
        render_pretty(result, console=console)
        return buffer.getvalue()

    def test_empty_result_shows_no_findings(self):
        output = self._capture(_make_result())
        assert "No vulnerabilities" in output

    def test_finding_appears_in_output(self):
        result = _make_result(findings=[_make_finding()])
        output = self._capture(result)
        assert "SQL Injection in login" in output
        assert "CWE-89" in output
        assert "app/auth.py" in output

    def test_metadata_in_output(self):
        result = _make_result(findings=[_make_finding()])
        output = self._capture(result)
        assert "claude-sonnet-4-6" in output
        assert "1000" in output  # input tokens

    def test_summary_table_for_multiple_findings(self):
        result = _make_result(findings=[
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
        ])
        output = self._capture(result)
        assert "Summary" in output
        assert "TOTAL" in output

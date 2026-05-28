"""Tests for the Pydantic models."""

import pytest
from pydantic import ValidationError

from sentinel.models import Confidence, Finding, ReviewResult, Severity


def _valid_finding_kwargs(**overrides):
    """Helper: returns a dict of valid kwargs for Finding, with overrides."""
    base = {
        "severity": Severity.HIGH,
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        "title": "SQL Injection in login handler",
        "file_path": "app/auth.py",
        "line_start": 42,
        "line_end": 45,
        "description": "User input is concatenated directly into SQL query.",
        "vulnerable_code": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
        "suggested_fix": "Use parameterized queries.",
        "confidence": Confidence.HIGH,
        "reasoning": "The user_id variable comes from request params unchecked.",
    }
    base.update(overrides)
    return base


class TestSeverity:
    def test_string_equality(self):
        assert Severity.HIGH == "high"

    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.HIGH >= Severity.HIGH

    def test_rank(self):
        assert Severity.CRITICAL.rank == 4
        assert Severity.INFO.rank == 0


class TestFinding:
    def test_valid_finding(self):
        f = Finding(**_valid_finding_kwargs())
        assert f.severity == Severity.HIGH

    def test_invalid_cwe_format_rejected(self):
        with pytest.raises(ValidationError):
            Finding(**_valid_finding_kwargs(cwe_id="CWE89"))

    def test_line_end_before_line_start_rejected(self):
        with pytest.raises(ValidationError):
            Finding(**_valid_finding_kwargs(line_start=10, line_end=5))

    def test_extra_fields_rejected(self):
        kwargs = _valid_finding_kwargs()
        kwargs["exploit_url"] = "https://example.com"  # hallucinated field
        with pytest.raises(ValidationError):
            Finding(**kwargs)

    def test_finding_is_frozen(self):
        f = Finding(**_valid_finding_kwargs())
        with pytest.raises(ValidationError):
            f.severity = Severity.LOW  # type: ignore[misc]


class TestReviewResult:
    def test_empty_result(self):
        r = ReviewResult(model="claude-sonnet-4-6")
        assert r.finding_count == 0
        assert not r.has_findings
        assert r.highest_severity is None

    def test_highest_severity(self):
        findings = [
            Finding(**_valid_finding_kwargs(severity=Severity.LOW)),
            Finding(**_valid_finding_kwargs(severity=Severity.CRITICAL)),
            Finding(**_valid_finding_kwargs(severity=Severity.MEDIUM)),
        ]
        r = ReviewResult(findings=findings, model="claude-sonnet-4-6")
        assert r.highest_severity == Severity.CRITICAL

    def test_findings_at_or_above(self):
        findings = [
            Finding(**_valid_finding_kwargs(severity=Severity.LOW)),
            Finding(**_valid_finding_kwargs(severity=Severity.HIGH)),
            Finding(**_valid_finding_kwargs(severity=Severity.CRITICAL)),
        ]
        r = ReviewResult(findings=findings, model="claude-sonnet-4-6")
        assert len(r.findings_at_or_above(Severity.HIGH)) == 2

    def test_count_by_severity(self):
        findings = [
            Finding(**_valid_finding_kwargs(severity=Severity.HIGH)),
            Finding(**_valid_finding_kwargs(severity=Severity.HIGH)),
            Finding(**_valid_finding_kwargs(severity=Severity.LOW)),
        ]
        r = ReviewResult(findings=findings, model="claude-sonnet-4-6")
        counts = r.count_by_severity()
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.LOW] == 1
        assert counts[Severity.CRITICAL] == 0

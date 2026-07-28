"""Tests for the Pydantic models."""

import pytest
from pydantic import ValidationError

from sentinel.models import Confidence, DiffFile, Finding, Language, ReviewResult, Severity


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

class TestDiffFile:
    """Tests for the DiffFile model added in Phase 2."""

    def _valid_kwargs(self, **overrides):
        base = {
            "file_path": "src/app/auth.py",
            "new_content": "import os\n\ndef login(user_id):\n    return user_id\n",
            "changed_line_ranges": [(3, 4)],
            "is_new_file": False,
            "language": Language.PYTHON,
        }
        base.update(overrides)
        return base

    def test_valid_diff_file(self):
        df = DiffFile(**self._valid_kwargs())
        assert df.file_path == "src/app/auth.py"
        assert df.changed_line_ranges == [(3, 4)]
        assert df.is_new_file is False

    def test_empty_file_path_rejected(self):
        with pytest.raises(ValidationError):
            DiffFile(**self._valid_kwargs(file_path=""))

    def test_empty_changed_ranges_allowed(self):
        """A file with no changed lines should still be constructible."""
        df = DiffFile(**self._valid_kwargs(changed_line_ranges=[]))
        assert df.changed_line_ranges == []
        assert df.total_changed_lines == 0

    def test_start_less_than_one_rejected(self):
        with pytest.raises(ValidationError):
            DiffFile(**self._valid_kwargs(changed_line_ranges=[(0, 5)]))

    def test_end_before_start_rejected(self):
        with pytest.raises(ValidationError):
            DiffFile(**self._valid_kwargs(changed_line_ranges=[(10, 5)]))

    def test_multiple_ranges_allowed(self):
        df = DiffFile(**self._valid_kwargs(
            changed_line_ranges=[(3, 5), (20, 22), (50, 55)]
        ))
        assert len(df.changed_line_ranges) == 3

    def test_extra_fields_rejected(self):
        kwargs = self._valid_kwargs()
        kwargs["mystery_field"] = "hello"
        with pytest.raises(ValidationError):
            DiffFile(**kwargs)

    def test_diff_file_is_frozen(self):
        df = DiffFile(**self._valid_kwargs())
        with pytest.raises(ValidationError):
            df.file_path = "different.py"  # type: ignore[misc]

    def test_is_new_file_defaults_false(self):
        kwargs = self._valid_kwargs()
        del kwargs["is_new_file"]
        df = DiffFile(**kwargs)
        assert df.is_new_file is False

    def test_is_pure_addition_matches_is_new_file(self):
        new_df = DiffFile(**self._valid_kwargs(is_new_file=True))
        old_df = DiffFile(**self._valid_kwargs(is_new_file=False))
        assert new_df.is_pure_addition is True
        assert old_df.is_pure_addition is False

    def test_total_changed_lines_single_range(self):
        df = DiffFile(**self._valid_kwargs(
            changed_line_ranges=[(10, 15)]
        ))
        # Inclusive: lines 10,11,12,13,14,15 = 6 lines
        assert df.total_changed_lines == 6

    def test_total_changed_lines_multiple_ranges(self):
        df = DiffFile(**self._valid_kwargs(
            changed_line_ranges=[(1, 3), (10, 12), (20, 20)]
        ))
        # 3 + 3 + 1 = 7 lines
        assert df.total_changed_lines == 7

    def test_total_changed_lines_empty(self):
        df = DiffFile(**self._valid_kwargs(changed_line_ranges=[]))
        assert df.total_changed_lines == 0

    def test_contains_line_inside_range(self):
        df = DiffFile(**self._valid_kwargs(
            changed_line_ranges=[(10, 15)]
        ))
        assert df.contains_line(12) is True
        assert df.contains_line(10) is True  # inclusive start
        assert df.contains_line(15) is True  # inclusive end

    def test_contains_line_outside_range(self):
        df = DiffFile(**self._valid_kwargs(
            changed_line_ranges=[(10, 15)]
        ))
        assert df.contains_line(9) is False
        assert df.contains_line(16) is False

    def test_contains_line_multiple_ranges(self):
        df = DiffFile(**self._valid_kwargs(
            changed_line_ranges=[(1, 3), (20, 25)]
        ))
        assert df.contains_line(2) is True
        assert df.contains_line(22) is True
        assert df.contains_line(10) is False
        
    def test_language_is_required(self):
        kwargs = self._valid_kwargs()
        del kwargs["language"]
        with pytest.raises(ValidationError):
            DiffFile(**kwargs)

    def test_language_field_stored_correctly(self):
        py = DiffFile(**self._valid_kwargs(language=Language.PYTHON))
        js = DiffFile(**self._valid_kwargs(language=Language.JAVASCRIPT))
        assert py.language == Language.PYTHON
        assert js.language == Language.JAVASCRIPT
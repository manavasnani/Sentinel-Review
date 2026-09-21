"""Tests for the comment formatter."""

from sentinel.github.comment_formatter import (
    findings_to_review_comments,
    format_finding_comment,
    format_review_summary,
)
from sentinel.models import (
    Confidence,
    Finding,
    Language,
    ReviewResult,
    Severity,
)


def _make_finding(**overrides) -> Finding:
    base = {
        "severity": Severity.HIGH,
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        "title": "SQL Injection",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 12,
        "description": "User input flows into SQL query.",
        "vulnerable_code": "query = f'SELECT * FROM users WHERE id = {uid}'",
        "suggested_fix": "Use parameterized queries.",
        "confidence": Confidence.HIGH,
        "reasoning": "Attacker-controlled input reaches SQL execution.",
    }
    base.update(overrides)
    return Finding(**base)


def _make_result(findings: list[Finding] | None = None) -> ReviewResult:
    return ReviewResult(
        findings=findings or [],
        files_analyzed=["src/app.py"],
        summary="test",
        model="claude-sonnet-4-6",
        input_tokens=1000,
        output_tokens=500,
        elapsed_seconds=5.0,
    )


class TestFormatFindingComment:
    def test_includes_severity_and_title(self):
        finding = _make_finding()
        comment = format_finding_comment(finding)
        assert "HIGH" in comment
        assert "SQL Injection" in comment

    def test_includes_cwe_and_owasp(self):
        finding = _make_finding()
        comment = format_finding_comment(finding)
        assert "CWE-89" in comment
        assert "A03:2021" in comment

    def test_includes_suggested_fix(self):
        finding = _make_finding()
        comment = format_finding_comment(finding)
        assert "parameterized queries" in comment

    def test_includes_reasoning_in_details(self):
        finding = _make_finding()
        comment = format_finding_comment(finding)
        assert "<details>" in comment
        assert "Reasoning" in comment

    def test_critical_severity_emoji(self):
        finding = _make_finding(severity=Severity.CRITICAL)
        comment = format_finding_comment(finding)
        assert "🔴" in comment


class TestFormatReviewSummary:
    def test_no_findings_message(self):
        result = _make_result(findings=[])
        summary = format_review_summary([result])
        assert "No security issues found" in summary

    def test_with_findings_shows_count(self):
        finding = _make_finding()
        result = _make_result(findings=[finding])
        summary = format_review_summary([result])
        assert "1" in summary
        assert "high" in summary

    def test_multiple_results_aggregated(self):
        f1 = _make_finding(severity=Severity.HIGH)
        f2 = _make_finding(severity=Severity.MEDIUM)
        r1 = _make_result(findings=[f1])
        r2 = _make_result(findings=[f2])
        summary = format_review_summary([r1, r2])
        assert "2" in summary


class TestFindingsToReviewComments:
    def test_one_finding_one_comment(self):
        finding = _make_finding(file_path="src/app.py", line_start=10)
        result = _make_result(findings=[finding])
        comments = findings_to_review_comments([result])
        assert len(comments) == 1
        assert comments[0].path == "src/app.py"
        assert comments[0].line == 10

    def test_multiple_findings_multiple_comments(self):
        f1 = _make_finding(line_start=10)
        f2 = _make_finding(line_start=20, line_end=22)
        result = _make_result(findings=[f1, f2])
        comments = findings_to_review_comments([result])
        assert len(comments) == 2

    def test_backslash_paths_normalized(self):
        finding = _make_finding(file_path="src\\app.py")
        result = _make_result(findings=[finding])
        comments = findings_to_review_comments([result])
        # post_review normalizes paths, but the comment should
        # preserve whatever the finding has
        assert comments[0].path == "src\\app.py"

    def test_empty_results_empty_comments(self):
        result = _make_result(findings=[])
        comments = findings_to_review_comments([result])
        assert comments == []
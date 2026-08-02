"""Tests for the Typer CLI."""

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.models import Confidence, Finding, ReviewResult, Severity, Language


runner = CliRunner()


def _stub_result(findings=None) -> ReviewResult:
    return ReviewResult(
        findings=findings or [],
        files_analyzed=["test.py"],
        summary="stub",
        model="claude-sonnet-4-6",
        input_tokens=100,
        output_tokens=20,
        elapsed_seconds=1.0,
    )


def _make_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        severity=severity,
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
        title="Test",
        file_path="test.py",
        line_start=1,
        line_end=2,
        description="x",
        vulnerable_code="x",
        suggested_fix="x",
        confidence=Confidence.HIGH,
        reasoning="x",
    )


class TestVersion:
    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "sentinel-review" in result.stdout


class TestReviewArgValidation:
    def test_no_args_exits_with_help(self):
        result = runner.invoke(app, ["review"])
        assert result.exit_code != 0

    def test_both_file_and_dir_rejected(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("x = 1")
        result = runner.invoke(app, [
            "review", "--file", str(f), "--dir", str(tmp_path),
        ])
        assert result.exit_code == 2

    def test_invalid_severity_threshold(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("x = 1")
        with patch("sentinel.cli.analyze_file", return_value=_stub_result()):
            result = runner.invoke(app, [
                "review", "--file", str(f), "--fail-on", "nonsense",
            ])
        assert result.exit_code == 2


class TestReviewFile:
    def test_clean_file_exits_zero(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1")
        with patch("sentinel.cli.analyze_file", return_value=_stub_result()):
            result = runner.invoke(app, ["review", "--file", str(f)])
        assert result.exit_code == 0

    def test_findings_below_threshold_exit_zero(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("x = 1")
        stub = _stub_result(findings=[_make_finding(Severity.LOW)])
        with patch("sentinel.cli.analyze_file", return_value=stub):
            result = runner.invoke(app, [
                "review", "--file", str(f), "--fail-on", "high",
            ])
        assert result.exit_code == 0

    def test_findings_above_threshold_exit_one(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("x = 1")
        stub = _stub_result(findings=[_make_finding(Severity.HIGH)])
        with patch("sentinel.cli.analyze_file", return_value=stub):
            result = runner.invoke(app, [
                "review", "--file", str(f), "--fail-on", "high",
            ])
        assert result.exit_code == 1

    def test_json_output(self, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("x = 1")
        stub = _stub_result(findings=[_make_finding()])
        with patch("sentinel.cli.analyze_file", return_value=stub):
            result = runner.invoke(app, [
                "review", "--file", str(f), "--output", "json",
            ])
        assert result.exit_code == 0
        assert '"findings"' in result.stdout
        assert "CWE-89" in result.stdout

class TestReviewDiffMode:
    def test_diff_from_stdin_with_findings(self, tmp_path, mocker):
        # Load a fixture diff
        fixture = Path("tests/fixtures/diffs/single_file_addition.diff")
        diff_text = fixture.read_text()

        # Stub analyze_diff_file to return a result with one finding
        stub_finding = Finding(
            severity=Severity.HIGH,
            cwe_id="CWE-916",
            owasp_category="A02:2021",
            title="MD5",
            file_path="src/app/auth.py",
            line_start=4,
            line_end=4,
            description="x",
            vulnerable_code="x",
            suggested_fix="x",
            confidence=Confidence.HIGH,
            reasoning="x",
        )
        stub_result = ReviewResult(
            findings=[stub_finding],
            files_analyzed=["src/app/auth.py"],
            summary="found MD5",
            model="claude-sonnet-4-6",
            input_tokens=100,
            output_tokens=50,
            elapsed_seconds=1.0,
            language=Language.PYTHON,
        )

        with patch("sentinel.cli.analyze_diff_file", return_value=stub_result):
            result = runner.invoke(
                app,
                ["review", "--diff", "--fail-on", "high"],
                input=diff_text,
            )

        assert result.exit_code == 1  # HIGH finding triggers fail-on

    def test_diff_mode_rejects_file_flag(self, tmp_path):
        result = runner.invoke(
            app,
            ["review", "--diff", "--file", "foo.py"],
        )
        assert result.exit_code == 2

    def test_diff_mode_empty_input(self):
        result = runner.invoke(app, ["review", "--diff"], input="")
        assert result.exit_code == 2

    def test_diff_mode_no_reviewable_files(self):
        # A diff with only README.md changes
        diff = """diff --git a/README.md b/README.md
index abc..def 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # Title
+New line
"""
        result = runner.invoke(app, ["review", "--diff"], input=diff)
        assert result.exit_code == 0  # nothing to analyze, exit clean
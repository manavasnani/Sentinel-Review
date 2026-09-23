"""Tests for the SARIF converter."""

import json

import pytest

from sentinel.models import (
    Confidence,
    Finding,
    ReviewResult,
    Severity,
)
from sentinel.sarif.converter import results_to_sarif, results_to_sarif_json


def _make_finding(**overrides) -> Finding:
    base = {
        "severity": Severity.HIGH,
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        "title": "SQL Injection",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 12,
        "description": "User input in SQL query.",
        "vulnerable_code": "query = f'SELECT * FROM users WHERE id = {uid}'",
        "suggested_fix": "Use parameterized queries.",
        "confidence": Confidence.HIGH,
        "reasoning": "Attacker input reaches SQL.",
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


class TestResultsToSarif:
    def test_valid_sarif_structure(self):
        finding = _make_finding()
        result = _make_result([finding])
        sarif = results_to_sarif([result])

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_tool_metadata(self):
        sarif = results_to_sarif([_make_result()])
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Sentinel Review"
        assert "version" in driver

    def test_single_finding_produces_one_result(self):
        finding = _make_finding()
        result = _make_result([finding])
        sarif = results_to_sarif([result])

        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CWE-89"

    def test_finding_location(self):
        finding = _make_finding(
            file_path="src/app.py", line_start=10, line_end=12
        )
        result = _make_result([finding])
        sarif = results_to_sarif([result])

        location = sarif["runs"][0]["results"][0]["locations"][0]
        phys = location["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "src/app.py"
        assert phys["region"]["startLine"] == 10
        assert phys["region"]["endLine"] == 12

    def test_backslash_paths_normalized(self):
        finding = _make_finding(file_path="src\\app.py")
        result = _make_result([finding])
        sarif = results_to_sarif([result])

        uri = sarif["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]["uri"]
        assert "\\" not in uri
        assert uri == "src/app.py"

    def test_severity_mapping(self):
        cases = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]
        for severity, expected_level in cases:
            finding = _make_finding(severity=severity)
            result = _make_result([finding])
            sarif = results_to_sarif([result])
            level = sarif["runs"][0]["results"][0]["level"]
            assert level == expected_level, f"{severity} should map to {expected_level}"

    def test_security_severity_score(self):
        finding = _make_finding(severity=Severity.CRITICAL)
        result = _make_result([finding])
        sarif = results_to_sarif([result])

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        score = rules[0]["properties"]["security-severity"]
        assert score == "9.5"

    def test_multiple_findings_same_cwe(self):
        f1 = _make_finding(cwe_id="CWE-89", line_start=10, line_end=12)
        f2 = _make_finding(cwe_id="CWE-89", line_start=20, line_end=22)
        result = _make_result([f1, f2])
        sarif = results_to_sarif([result])

        # Two results but only one rule
        assert len(sarif["runs"][0]["results"]) == 2
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1

    def test_multiple_findings_different_cwes(self):
        f1 = _make_finding(cwe_id="CWE-89", line_start=10, line_end=12)
        f2 = _make_finding(cwe_id="CWE-78", line_start=20, line_end=22)
        result = _make_result([f1, f2])
        sarif = results_to_sarif([result])

        # Two results and two rules
        assert len(sarif["runs"][0]["results"]) == 2
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 2

    def test_empty_results(self):
        result = _make_result([])
        sarif = results_to_sarif([result])

        assert len(sarif["runs"][0]["results"]) == 0
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0

    def test_fingerprint_for_deduplication(self):
        finding = _make_finding(
            file_path="src/app.py", cwe_id="CWE-89", line_start=10
        )
        result = _make_result([finding])
        sarif = results_to_sarif([result])

        fingerprint = sarif["runs"][0]["results"][0]["fingerprints"]
        assert "sentinel/v1" in fingerprint
        assert fingerprint["sentinel/v1"] == "src/app.py:CWE-89:10"

    def test_help_uri_links_to_cwe(self):
        finding = _make_finding(cwe_id="CWE-89")
        result = _make_result([finding])
        sarif = results_to_sarif([result])

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "89" in rule["helpUri"]
        assert "cwe.mitre.org" in rule["helpUri"]

    def test_suggested_fix_in_fixes(self):
        finding = _make_finding(suggested_fix="Use parameterized queries.")
        result = _make_result([finding])
        sarif = results_to_sarif([result])

        fixes = sarif["runs"][0]["results"][0]["fixes"]
        assert len(fixes) == 1
        assert "parameterized" in fixes[0]["description"]["text"]

    def test_multiple_results_aggregated(self):
        f1 = _make_finding(file_path="a.py", line_start=1, line_end=1)
        f2 = _make_finding(file_path="b.py", line_start=5, line_end=5)
        r1 = _make_result([f1])
        r2 = _make_result([f2])
        sarif = results_to_sarif([r1, r2])

        assert len(sarif["runs"][0]["results"]) == 2


class TestResultsToSarifJson:
    def test_valid_json_output(self):
        result = _make_result([_make_finding()])
        json_str = results_to_sarif_json([result])
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    def test_indent_parameter(self):
        result = _make_result([_make_finding()])
        compact = results_to_sarif_json([result], indent=0)
        pretty = results_to_sarif_json([result], indent=2)
        # Pretty-printed should be longer due to whitespace
        assert len(pretty) > len(compact)
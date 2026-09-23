"""
Convert Sentinel ReviewResult objects to SARIF 2.1.0 format.

SARIF (Static Analysis Results Interchange Format) is the standard format
for static analysis tool output. GitHub's code scanning feature reads SARIF
files and displays results in the Security tab.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from sentinel import __version__
from sentinel.models import Finding, ReviewResult, Severity


# Map Sentinel severity to SARIF level
_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Map Sentinel severity to SARIF security-severity score (0.0-10.0)
# These align with the CVSS-like scoring GitHub uses for sorting
_SEVERITY_TO_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def results_to_sarif(results: list[ReviewResult]) -> dict[str, Any]:
    """
    Convert a list of ReviewResult objects to a SARIF 2.1.0 document.

    Args:
        results: List of ReviewResult objects from the analyzer.

    Returns:
        A dict representing the complete SARIF JSON document.
    """
    # Collect all unique rules (CWE IDs) across all findings
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for review in results:
        for finding in review.findings:
            rule_id = finding.cwe_id

            # Register the rule if we haven't seen this CWE before
            if rule_id not in rules:
                rules[rule_id] = _build_rule(finding)

            sarif_results.append(_build_result(finding, rule_id))

    # Build the final SARIF document
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel Review",
                        "version": __version__,
                        "informationUri": "https://github.com/manavasnani/Sentinel-Review",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return sarif


def results_to_sarif_json(
    results: list[ReviewResult],
    indent: int = 2,
) -> str:
    """
    Convert results to a SARIF JSON string.

    Convenience wrapper around results_to_sarif() that handles
    serialization.
    """
    sarif = results_to_sarif(results)
    return json.dumps(sarif, indent=indent)


def _build_rule(finding: Finding) -> dict[str, Any]:
    """
    Build a SARIF rule object from a Finding.

    Rules are keyed by CWE ID. Each rule appears once in the SARIF
    document even if multiple findings share the same CWE.
    """
    return {
        "id": finding.cwe_id,
        "name": finding.cwe_id,
        "shortDescription": {
            "text": f"{finding.cwe_id}: {finding.title}",
        },
        "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe_id.split('-')[1]}.html",
        "properties": {
            "tags": ["security"],
            "security-severity": _SEVERITY_TO_SCORE.get(
                finding.severity, "5.0"
            ),
        },
    }


def _build_result(finding: Finding, rule_id: str) -> dict[str, Any]:
    """
    Build a SARIF result object from a Finding.

    Each result represents one instance of a rule violation at a
    specific location in the code.
    """
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {
            "text": finding.description,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path.replace("\\", "/"),
                    },
                    "region": {
                        "startLine": finding.line_start,
                        "endLine": finding.line_end,
                    },
                },
            }
        ],
        "fixes": [
            {
                "description": {
                    "text": finding.suggested_fix,
                },
            }
        ],
    }

    # Add fingerprint for deduplication across runs
    # GitHub uses this to track whether an alert is new or existing
    result["fingerprints"] = {
        "sentinel/v1": f"{finding.file_path}:{finding.cwe_id}:{finding.line_start}",
    }

    return result
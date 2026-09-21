"""
Format security findings as GitHub PR review comments.

Each finding becomes an inline comment on the specific line where the
vulnerability was detected. The top-level review body summarizes all
findings across all files.
"""

from __future__ import annotations

from sentinel.github.pr_client import ReviewComment
from sentinel.models import Finding, ReviewResult, Severity


# Severity -> emoji mapping for visual scanning in PR comments
_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def format_finding_comment(finding: Finding) -> str:
    """
    Format a single finding as a markdown comment body.

    The comment is designed to be readable in GitHub's PR review UI:
    - Severity and CWE in the header for quick scanning
    - Description explains the issue
    - Suggested fix gives actionable remediation
    - Collapsible details section for reasoning (doesn't clutter the view)
    """
    emoji = _SEVERITY_EMOJI.get(finding.severity, "")
    header = f"{emoji} **{finding.severity.value.upper()}**: {finding.title}"

    parts = [
        header,
        "",
        f"**CWE:** {finding.cwe_id} | **OWASP:** {finding.owasp_category} | **Confidence:** {finding.confidence.value}",
        "",
        finding.description,
        "",
        f"**Suggested fix:**",
        finding.suggested_fix,
    ]

    # Add reasoning in a collapsible section
    if finding.reasoning:
        parts.extend([
            "",
            "<details>",
            "<summary>Reasoning</summary>",
            "",
            finding.reasoning,
            "",
            "</details>",
        ])

    return "\n".join(parts)


def format_review_summary(results: list[ReviewResult]) -> str:
    """
    Format the top-level review body summarizing all findings.

    This appears as the main review comment at the top of the review,
    before any inline comments.
    """
    total_findings = sum(len(r.findings) for r in results)
    total_files = sum(len(r.files_analyzed) for r in results)

    if total_findings == 0:
        return (
            "## Sentinel Review\n\n"
            f"Reviewed {total_files} changed file(s). "
            "No security issues found."
        )

    # Count by severity
    severity_counts: dict[Severity, int] = {}
    for result in results:
        for finding in result.findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )

    severity_summary = ", ".join(
        f"{count} {sev.value}"
        for sev, count in sorted(
            severity_counts.items(),
            key=lambda x: list(Severity).index(x[0]),
        )
    )

    # Token/cost summary
    total_input = sum(r.input_tokens for r in results)
    total_output = sum(r.output_tokens for r in results)
    cost = total_input * 3 / 1_000_000 + total_output * 15 / 1_000_000

    lines = [
        "## Sentinel Review",
        "",
        f"Found **{total_findings}** security issue(s) across "
        f"**{total_files}** file(s): {severity_summary}.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Files reviewed | {total_files} |",
        f"| Findings | {total_findings} |",
        f"| Estimated cost | ${cost:.3f} |",
        "",
        "Each finding is posted as an inline comment on the affected line.",
    ]

    return "\n".join(lines)


def findings_to_review_comments(
    results: list[ReviewResult],
) -> list[ReviewComment]:
    """
    Convert all findings from all results into ReviewComment objects.

    Each finding becomes one inline comment positioned at the finding's
    line_start. The file path is taken from the finding itself.
    """
    comments: list[ReviewComment] = []

    for result in results:
        for finding in result.findings:
            comment = ReviewComment(
                path=finding.file_path,
                line=finding.line_start,
                body=format_finding_comment(finding),
            )
            comments.append(comment)

    return comments
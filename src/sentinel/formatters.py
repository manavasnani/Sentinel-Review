"""
Output formatters for Sentinel Review.

Renders a ReviewResult in two formats:
    - JSON: machine-readable, for piping to other tools or CI artifacts.
    - Pretty: human-readable terminal output using `rich`.

Formatters are pure functions: they take a ReviewResult and return a string
(or write directly to a Console). They never call the API or read from disk.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from sentinel.models import Finding, ReviewResult, Severity


# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------
#
# Rich color names. These render nicely on both dark and light terminal themes.
# Bold for the headline severities (critical/high) so they catch the eye in
# a long review.

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

CONFIDENCE_GLYPHS: dict[str, str] = {
    "high": "●●●",
    "medium": "●●○",
    "low": "●○○",
}


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

def to_json(result: ReviewResult, indent: int = 2) -> str:
    """
    Serialize a ReviewResult to JSON.

    Uses Pydantic's `model_dump_json` so datetimes, enums, and other types
    serialize correctly without custom encoders.

    Args:
        result: The review result to serialize.
        indent: JSON indentation. Use 0 or None for compact output.

    Returns:
        JSON string.
    """
    # model_dump_json handles datetime, enum, and other special types correctly
    return result.model_dump_json(indent=indent)


def to_dict(result: ReviewResult) -> dict[str, Any]:
    """
    Serialize a ReviewResult to a plain dict.

    Useful for embedding in larger JSON structures or for tests that need
    to assert on individual fields.
    """
    return result.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Pretty formatter
# ---------------------------------------------------------------------------

def render_pretty(result: ReviewResult, console: Console | None = None) -> None:
    """
    Render a ReviewResult to the terminal using rich formatting.

    Args:
        result: The review result to render.
        console: Optional Console to render to. Defaults to a new one (stdout).
    """
    console = console or Console()

    _render_header(result, console)

    if not result.has_findings:
        console.print()
        console.print(Panel.fit(
            "[bold green]✓ No vulnerabilities found.[/bold green]\n"
            f"[dim]{result.summary}[/dim]" if result.summary else "",
            border_style="green",
        ))
        _render_metadata(result, console)
        return

    console.print()
    for idx, finding in enumerate(result.findings, start=1):
        _render_finding(finding, idx, console)
        console.print()

    _render_summary_table(result, console)
    _render_metadata(result, console)


def _render_header(result: ReviewResult, console: Console) -> None:
    """Render the top banner with file list and finding count."""
    files = ", ".join(result.files_analyzed) or "(none)"
    title = Text("Sentinel Review", style="bold cyan")
    subtitle = Text(f"{files}", style="dim")

    header = Text.assemble(title, "  ", subtitle)
    console.print(header)
    console.rule(style="dim")


def _render_finding(finding: Finding, index: int, console: Console) -> None:
    """Render a single finding as a rich Panel."""
    sev_style = SEVERITY_STYLES.get(finding.severity, "white")
    conf_glyph = CONFIDENCE_GLYPHS.get(finding.confidence.value, "?")

    # Header line: [SEVERITY] Title  (CWE-XX • confidence ●●○)
    header = Text.assemble(
        (f"[{finding.severity.value.upper()}] ", sev_style),
        (finding.title, "bold"),
        "  ",
        (f"({finding.cwe_id} • {conf_glyph} {finding.confidence.value})", "dim"),
    )

    # Location line
    location = Text(
        f"{finding.file_path}:{finding.line_start}"
        + (f"-{finding.line_end}" if finding.line_end != finding.line_start else ""),
        style="cyan",
    )

    # Body
    body = Text()
    body.append("Description: ", style="bold")
    body.append(finding.description)
    body.append("\n\n")
    body.append("Why it's a problem: ", style="bold")
    body.append(finding.reasoning)
    body.append("\n\n")
    body.append("OWASP: ", style="bold")
    body.append(finding.owasp_category)

    # Vulnerable code block
    code_block = Syntax(
        finding.vulnerable_code,
        "python",
        theme="ansi_dark",
        line_numbers=False,
        word_wrap=True,
    )

    # Suggested fix
    fix = Text()
    fix.append("Suggested fix:\n", style="bold green")
    fix.append(finding.suggested_fix)

    # Compose into a panel
    panel_content = Text.assemble(
        header, "\n",
        location, "\n\n",
        body,
    )

    console.print(Panel(
        panel_content,
        title=f"Finding #{index}",
        title_align="left",
        border_style=sev_style,
        padding=(1, 2),
    ))
    console.print()
    console.print("[bold]Vulnerable code:[/bold]")
    console.print(code_block)
    console.print()
    console.print(fix)


def _render_summary_table(result: ReviewResult, console: Console) -> None:
    """Render a summary table of findings by severity."""
    counts = result.count_by_severity()

    table = Table(
        title="Summary",
        show_header=True,
        header_style="bold",
        border_style="dim",
    )
    table.add_column("Severity", justify="left")
    table.add_column("Count", justify="right")

    # Render in severity rank order (critical first)
    for severity in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        count = counts.get(severity, 0)
        if count == 0:
            continue
        style = SEVERITY_STYLES[severity]
        table.add_row(
            Text(severity.value.upper(), style=style),
            Text(str(count), style=style),
        )

    table.add_section()
    table.add_row(
        Text("TOTAL", style="bold"),
        Text(str(result.finding_count), style="bold"),
    )

    console.print()
    console.print(table)


def _render_metadata(result: ReviewResult, console: Console) -> None:
    """Render the metadata footer (model, tokens, latency)."""
    metadata = Text(
        f"Model: {result.model}  •  "
        f"Tokens: {result.input_tokens} in / {result.output_tokens} out  •  "
        f"Time: {result.elapsed_seconds:.2f}s",
        style="dim",
    )
    console.print()
    console.rule(style="dim")
    console.print(metadata)
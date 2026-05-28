"""
Command-line interface for Sentinel Review.

Wires the analyzer and formatters together behind a Typer-based CLI.
The CLI is intentionally thin: it parses arguments, calls into the rest
of the package, and formats output. All real logic lives elsewhere.

Entry points:
    sentinel review --file <path>
    sentinel review --dir <path>
    sentinel version
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from sentinel import __version__
from sentinel.analyzer import analyze_file
from sentinel.config import SentinelConfig, get_config
from sentinel.exceptions import (
    AnalysisError,
    APIError,
    ConfigurationError,
    ParseError,
    SentinelError,
)
from sentinel.formatters import render_pretty, to_json
from sentinel.models import ReviewResult, Severity


app = typer.Typer(
    name="sentinel",
    help="AI-powered secure code review. Reviews Python files for security "
         "vulnerabilities using Claude.",
    no_args_is_help=True,
    add_completion=False,
)

# Two consoles: stdout for output, stderr for messages. This means
# `sentinel review --output json > findings.json` cleanly captures JSON in
# the file while status messages go to the terminal.
stdout_console = Console()
stderr_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Common options (reused across commands)
# ---------------------------------------------------------------------------

OutputFormat = Annotated[
    str,
    typer.Option(
        "--output", "-o",
        help="Output format: 'pretty' (terminal) or 'json' (machine-readable).",
        case_sensitive=False,
    ),
]

ModelOverride = Annotated[
    str | None,
    typer.Option(
        "--model", "-m",
        help="Override the Claude model. Defaults to SENTINEL_MODEL env var or "
             "the package default.",
    ),
]

SeverityThreshold = Annotated[
    str | None,
    typer.Option(
        "--fail-on",
        help="Exit non-zero if any finding meets or exceeds this severity. "
             "One of: critical, high, medium, low, info.",
    ),
]

VerboseFlag = Annotated[
    bool,
    typer.Option(
        "--verbose", "-v",
        help="Show DEBUG-level logging (API calls, retries, timing).",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool) -> None:
    """Set up logging level based on the verbose flag."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _build_config(model_override: str | None) -> SentinelConfig:
    """Build config, applying any CLI overrides on top of env values."""
    config = get_config()
    if model_override:
        # Frozen dataclasses don't support direct mutation; rebuild instead.
        from dataclasses import replace
        config = replace(config, model=model_override)
    return config


def _parse_severity(value: str | None) -> Severity | None:
    """Convert a string like 'high' to a Severity enum, or None if not given."""
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        stderr_console.print(
            f"[red]Invalid severity: {value!r}. Must be one of: {valid}[/red]"
        )
        raise typer.Exit(code=2)


def _emit_result(result: ReviewResult, output_format: str) -> None:
    """Render a single ReviewResult in the chosen format."""
    fmt = output_format.lower()
    if fmt == "json":
        # Write JSON to stdout so it can be piped/redirected cleanly
        print(to_json(result))
    elif fmt == "pretty":
        render_pretty(result, console=stdout_console)
    else:
        stderr_console.print(
            f"[red]Invalid output format: {output_format!r}. "
            f"Use 'pretty' or 'json'.[/red]"
        )
        raise typer.Exit(code=2)


def _exit_code_for_threshold(
    result: ReviewResult,
    threshold: Severity | None,
) -> int:
    """
    Determine the process exit code based on findings and threshold.

    Returns:
        0 if no findings meet the threshold (or no threshold set).
        1 if at least one finding meets or exceeds the threshold.
    """
    if threshold is None:
        return 0
    if result.findings_at_or_above(threshold):
        return 1
    return 0

def _handle_error(e: Exception) -> int:
    """Map a SentinelError to a formatted message and exit code."""
    if isinstance(e, ConfigurationError):
        stderr_console.print(f"[red]Configuration error:[/red] {e}")
        return 2
    if isinstance(e, AnalysisError):
        stderr_console.print(f"[red]Analysis error:[/red] {e}")
        return 2
    if isinstance(e, APIError):
        stderr_console.print(f"[red]API error:[/red] {e}")
        return 3
    if isinstance(e, ParseError):
        stderr_console.print(f"[red]Parse error:[/red] {e}")
        return 3
    stderr_console.print(f"[red]Error:[/red] {e}")
    return 1


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def review(
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="Path to a single source file to review."),
    ] = None,
    directory: Annotated[
        Optional[Path],
        typer.Option("--dir", "-d", help="Path to a directory; reviews all .py files."),
    ] = None,
    output: OutputFormat = "pretty",
    model: ModelOverride = None,
    fail_on: SeverityThreshold = None,
    verbose: VerboseFlag = False,
) -> None:
    """
    Review a file or directory for security vulnerabilities.

    Examples:

        sentinel review --file app/auth.py
        sentinel review --dir src/
        sentinel review --file app.py --output json > findings.json
        sentinel review --file app.py --fail-on high
    """
    _configure_logging(verbose)

    if file is None and directory is None:
        stderr_console.print(
            "[red]Specify --file or --dir.[/red]\n"
            "Run 'sentinel review --help' for usage."
        )
        raise typer.Exit(code=2)
    if file is not None and directory is not None:
        stderr_console.print("[red]Use --file OR --dir, not both.[/red]")
        raise typer.Exit(code=2)

    try:
        config = _build_config(model)
        threshold = _parse_severity(fail_on)

        if file is not None:
            result = analyze_file(file, config=config)
            _emit_result(result, output)
            sys.exit(_exit_code_for_threshold(result, threshold))

        # Directory mode
        targets = _collect_python_files(directory)
        if not targets:
            stderr_console.print(
                f"[yellow]No .py files found in {directory}.[/yellow]"
            )
            raise typer.Exit(code=0)

        if output.lower() == "pretty":
            stderr_console.print(
                f"[dim]Reviewing {len(targets)} file(s)...[/dim]"
            )

        aggregated_exit = 0
        for target in targets:
            if output.lower() == "pretty":
                stderr_console.print(f"\n[bold cyan]→ {target}[/bold cyan]")
            result = analyze_file(target, config=config)
            _emit_result(result, output)
            if _exit_code_for_threshold(result, threshold) != 0:
                aggregated_exit = 1

        sys.exit(aggregated_exit)

    except SentinelError as e:
        sys.exit(_handle_error(e))


def _collect_python_files(directory: Path) -> list[Path]:
    """
    Walk a directory and return all .py files, sorted for deterministic order.

    Skips common noise directories (.venv, __pycache__, node_modules, .git).
    """
    if not directory.exists():
        raise AnalysisError(f"Directory not found: {directory}")
    if not directory.is_dir():
        raise AnalysisError(f"Not a directory: {directory}")

    skip_dirs = {".venv", "venv", "__pycache__", "node_modules", ".git", ".tox"}
    files: list[Path] = []
    for path in directory.rglob("*.py"):
        if any(part in skip_dirs for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


@app.command()
def version() -> None:
    """Print the Sentinel Review version and exit."""
    stdout_console.print(f"sentinel-review {__version__}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------
#
# `python -m sentinel.cli` and the `sentinel` console script (defined in
# pyproject.toml [project.scripts]) both route here.

if __name__ == "__main__":
    app()
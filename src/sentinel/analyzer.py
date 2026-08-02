"""
Core analyzer module.

Handles the interaction with the Anthropic API to perform security code review.
Takes source code as input, sends it to Claude with a security-focused system
prompt and a structured-output tool definition, and returns parsed findings.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from anthropic import Anthropic, APIStatusError, APITimeoutError, RateLimitError

from sentinel.config import SentinelConfig, get_config
from sentinel.exceptions import (
    AnalysisError,
    APIError,
    ConfigurationError,
    ParseError,
)
from sentinel.models import DiffFile, Finding, Language, ReviewResult, Severity
from sentinel.prompts import (
    SECURITY_REVIEW_SYSTEM_PROMPT,
    format_review_request,
    get_prompt_module,
)

from sentinel.prompts.diff_addendum import DIFF_MODE_ADDENDUM

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool schema for structured output
# ---------------------------------------------------------------------------

REPORT_FINDINGS_TOOL: dict[str, Any] = {
    "name": "report_security_findings",
    "description": (
        "Report all security vulnerabilities discovered in the reviewed code. "
        "Call this tool exactly once at the end of the review with the complete "
        "list of findings. If no vulnerabilities are found, call it with an "
        "empty findings list."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "description": "List of security findings discovered in the code.",
                "items": {
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Severity of the vulnerability.",
                        },
                        "cwe_id": {
                            "type": "string",
                            "description": "CWE identifier, e.g. 'CWE-89' for SQL injection.",
                        },
                        "owasp_category": {
                            "type": "string",
                            "description": (
                                "OWASP Top 10 category, e.g. 'A03:2021 - Injection'."
                            ),
                        },
                        "title": {
                            "type": "string",
                            "description": "Short title summarizing the finding.",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Path of the file containing the finding.",
                        },
                        "line_start": {
                            "type": "integer",
                            "description": "First line of the vulnerable code (1-indexed).",
                        },
                        "line_end": {
                            "type": "integer",
                            "description": "Last line of the vulnerable code (1-indexed).",
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed explanation of the vulnerability.",
                        },
                        "vulnerable_code": {
                            "type": "string",
                            "description": "The exact code snippet that is vulnerable.",
                        },
                        "suggested_fix": {
                            "type": "string",
                            "description": "Concrete remediation, ideally with example code.",
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["high", "medium", "low"],
                            "description": (
                                "How confident the reviewer is that this is a real "
                                "vulnerability, not a false positive."
                            ),
                        },
                        "reasoning": {
                            "type": "string",
                            "description": (
                                "Why this is considered a vulnerability. Used for "
                                "explainability and to help developers learn."
                            ),
                        },
                    },
                    "required": [
                        "severity",
                        "cwe_id",
                        "owasp_category",
                        "title",
                        "file_path",
                        "line_start",
                        "line_end",
                        "description",
                        "vulnerable_code",
                        "suggested_fix",
                        "confidence",
                        "reasoning",
                    ],
                },
            },
            "summary": {
                "type": "string",
                "description": (
                    "Brief overall summary of the review. Mention number of "
                    "findings, highest severity, and general code quality."
                ),
            },
        },
        "required": ["findings", "summary"],
    },
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_client(config: SentinelConfig) -> Anthropic:
    """Construct the Anthropic client from config."""
    if not config.api_key:
        raise ConfigurationError(
            "ANTHROPIC_API_KEY is not set. Add it to your environment or .env file."
        )
    return Anthropic(api_key=config.api_key)


def _call_api_with_retry(
    client: Anthropic,
    config: SentinelConfig,
    system_prompt: str,
    user_message: str,
) -> Any:
    """
    Call the Anthropic API with exponential backoff retry on transient errors.

    Retries on rate limits and timeouts. Does NOT retry on auth errors or
    bad-request errors, which indicate a problem with our code or config.
    """
    last_error: Exception | None = None
    delay = config.initial_retry_delay

    for attempt in range(1, config.max_retries + 1):
        try:
            logger.debug(
                "Calling Anthropic API (attempt %d/%d, model=%s)",
                attempt,
                config.max_retries,
                config.model,
            )
            response = client.messages.create(
                model=config.model,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                system=system_prompt,
                tools=[REPORT_FINDINGS_TOOL],
                tool_choice={"type": "tool", "name": "report_security_findings"},
                messages=[{"role": "user", "content": user_message}],
            )
            return response

        except RateLimitError as e:
            last_error = e
            logger.warning(
                "Rate limited on attempt %d. Waiting %.1fs before retry.",
                attempt,
                delay,
            )
            time.sleep(delay)
            delay *= 2

        except APITimeoutError as e:
            last_error = e
            logger.warning(
                "API timeout on attempt %d. Waiting %.1fs before retry.",
                attempt,
                delay,
            )
            time.sleep(delay)
            delay *= 2

        except APIStatusError as e:
            # 4xx errors (except 429) are not retryable - they indicate a real
            # problem with the request itself.
            if 400 <= e.status_code < 500 and e.status_code != 429:
                raise APIError(
                    f"Anthropic API rejected the request "
                    f"({e.status_code}): {e.message}"
                ) from e
            last_error = e
            logger.warning(
                "API status error %d on attempt %d. Retrying.",
                e.status_code,
                attempt,
            )
            time.sleep(delay)
            delay *= 2

    raise APIError(
        f"Anthropic API failed after {config.max_retries} attempts. "
        f"Last error: {last_error}"
    ) from last_error


def _extract_tool_input(response: Any) -> dict[str, Any]:
    """
    Pull the tool_use block out of the Claude response.

    Because we forced tool_choice, the response must contain exactly one
    tool_use block. If it doesn't, something has gone wrong.
    """
    for block in response.content:
        if getattr(block, "type", None) == "tool_use":
            return block.input  # type: ignore[no-any-return]

    raise ParseError(
        "Response did not contain a tool_use block. "
        "This usually means the model refused or the API changed."
    )


def _parse_findings(
    tool_input: dict[str, Any],
    file_path: str,
) -> tuple[list[Finding], str]:
    """Validate the model's output through the Pydantic schema."""
    raw_findings = tool_input.get("findings", [])
    summary = tool_input.get("summary", "")

    findings: list[Finding] = []
    for idx, raw in enumerate(raw_findings):
        try:
            # Make sure file_path is set even if the model omits it
            raw.setdefault("file_path", file_path)
            findings.append(Finding(**raw))
        except Exception as e:
            # Don't crash the whole review for one bad finding - log and skip
            logger.warning(
                "Skipping malformed finding #%d for %s: %s",
                idx,
                file_path,
                e,
            )

    return findings, summary

def _call_api_and_parse(
    system_prompt: str,
    user_message: str,
    file_path: str,
    config: SentinelConfig,
) -> ReviewResult:
    """
    Shared API interaction used by analyze_code() and analyze_diff_file().

    Handles:
      - Building the Anthropic client
      - Calling the API with retry logic
      - Extracting the tool_use response
      - Parsing findings via Pydantic
      - Assembling the ReviewResult with timing and token counts

    Args:
        system_prompt: The full system prompt (may include diff-mode addendum).
        user_message: The user-facing message (code + few-shot examples).
        file_path: Logical path for the reviewed code. Used in findings.
        config: Configuration for the API client.

    Returns:
        ReviewResult with findings, summary, token usage, and timing.

    Raises:
        APIError: API call failed after all retries.
        ParseError: Response could not be parsed.
    """
    client = _build_client(config)

    start = time.perf_counter()
    response = _call_api_with_retry(
        client=client,
        config=config,
        system_prompt=system_prompt,
        user_message=user_message,
    )
    elapsed = time.perf_counter() - start

    tool_input = _extract_tool_input(response)
    findings, summary = _parse_findings(tool_input, file_path)

    usage = getattr(response, "usage", None)
    input_tokens = getattr(usage, "input_tokens", 0) if usage else 0
    output_tokens = getattr(usage, "output_tokens", 0) if usage else 0

    logger.info(
        "Analyzed %s: %d findings, %d input + %d output tokens, %.2fs",
        file_path,
        len(findings),
        input_tokens,
        output_tokens,
        elapsed,
    )

    return ReviewResult(
        findings=findings,
        files_analyzed=[file_path],
        summary=summary,
        model=config.model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        elapsed_seconds=elapsed,
    )

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_code(
    code: str,
    file_path: str = "<inline>",
    config: SentinelConfig | None = None,
) -> ReviewResult:
    """
    Analyze a string of source code for security vulnerabilities.

    Args:
        code: Source code to review.
        file_path: Logical file path for the code. Used in findings and prompts.
        config: Optional config override. Defaults to env-based config.

    Returns:
        ReviewResult with findings, summary, token usage, and timing.

    Raises:
        ConfigurationError: API key is missing.
        APIError: API call failed after all retries.
        ParseError: Response could not be parsed.
    """
    config = config or get_config()
    user_message = format_review_request(code=code, file_path=file_path)

    return _call_api_and_parse(
        system_prompt=SECURITY_REVIEW_SYSTEM_PROMPT,
        user_message=user_message,
        file_path=file_path,
        config=config,
    )


def analyze_file(
    path: str | Path,
    config: SentinelConfig | None = None,
) -> ReviewResult:
    """
    Analyze a single file on disk for security vulnerabilities.

    Args:
        path: Path to the source file.
        config: Optional config override.

    Returns:
        ReviewResult for the file.

    Raises:
        AnalysisError: File does not exist or cannot be read as UTF-8.
        ConfigurationError, APIError, ParseError: See analyze_code.
    """
    file_path = Path(path)

    if not file_path.exists():
        raise AnalysisError(f"File not found: {file_path}")
    if not file_path.is_file():
        raise AnalysisError(f"Not a regular file: {file_path}")

    try:
        code = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise AnalysisError(
            f"Could not read {file_path} as UTF-8. Binary files are not supported."
        ) from e

    return analyze_code(
        code=code,
        file_path=str(file_path),
        config=config,
    )

# ---------------------------------------------------------------------------
# Diff-mode analysis (Phase 2)
# ---------------------------------------------------------------------------

def analyze_diff_file(
    diff_file: DiffFile,
    config: SentinelConfig | None = None,
) -> ReviewResult:
    """
    Analyze a DiffFile in diff mode.

    Focuses the model's attention on the lines that changed in the PR,
    with immediate context provided for reference. Returns a ReviewResult
    with findings scoped to the changed lines.

    Behavior differs from analyze_file() in three ways:
      1. The system prompt is language-specific + diff-mode addendum.
      2. The code is formatted with [CHANGED]/[CONTEXT] line markers.
      3. Line numbers in findings refer to the new file (post-merge).

    Args:
        diff_file: The parsed DiffFile from the diff parser.
        config: Optional configuration override. If None, uses env-based
                config as loaded by config.get_config().

    Returns:
        ReviewResult with findings, language set to diff_file.language.

    Raises:
        APIError: If the Anthropic API call fails after retries.
        ParseError: If the response cannot be parsed into findings.
        AnalysisError: For other unexpected errors.
    """
    cfg = config or get_config()

    # Get the language-specific prompt module and combine with diff addendum
    prompt_module = get_prompt_module(diff_file.language)
    system_prompt = prompt_module.SECURITY_REVIEW_SYSTEM_PROMPT + DIFF_MODE_ADDENDUM

    # Format the user message with change markers
    user_message = _format_diff_review_request(
        diff_file=diff_file,
        prompt_module=prompt_module,
    )

    # Call the API (reuses the same underlying request/retry logic)
    review_result = _call_api_and_parse(
        system_prompt=system_prompt,
        user_message=user_message,
        file_path=diff_file.file_path,
        config=cfg,
    )

    # Tag the result with the language for downstream routing (formatters,
    # comment generators, SARIF output, etc.)
    return review_result.model_copy(update={"language": diff_file.language})


def _format_diff_review_request(
    diff_file: DiffFile,
    prompt_module,
) -> str:
    """
    Format the user message for diff-mode analysis.

    The message contains:
      1. The few-shot examples from the language-specific prompt module.
      2. The file path.
      3. The code with per-line [CHANGED] or [CONTEXT] markers.

    For new files (is_new_file=True), the markers are omitted since every
    line is a change; the model reviews the whole content normally.
    """
    few_shot = prompt_module.FEW_SHOT_EXAMPLES
    fence = chr(96) * 3

    if diff_file.is_new_file:
        # New file: every line is a change, no markers needed
        marked_code = prompt_module._add_line_numbers(diff_file.new_content)
        mode_note = (
            "This is a NEW file added in this PR. Every line is a change. "
            "Review the entire file for security issues."
        )
    else:
        marked_code = _add_change_markers(
            diff_file.new_content, diff_file.changed_line_ranges
        )
        mode_note = (
            "This is a MODIFIED file. Only the lines marked [CHANGED] were "
            "added or modified in this PR. Lines marked [CONTEXT] are shown "
            "for reference. Focus your review on the [CHANGED] lines."
        )

    return f"""\
{few_shot}

---

Now review the following pull request diff. {mode_note}

Report vulnerabilities by calling the `report_security_findings` tool. \
Use the line numbers shown for `line_start` and `line_end`.

File: {diff_file.file_path}

{fence}
{marked_code}
{fence}
"""


def _add_change_markers(
    content: str,
    changed_ranges: list[tuple[int, int]],
) -> str:
    """
    Format code with per-line [CHANGED] or [CONTEXT] markers.

    Each line is prefixed with its line number and a marker indicating
    whether that line was changed in the PR. The output looks like:

         1  [CONTEXT] def hello():
         2  [CONTEXT]     return "world"
         3  [CHANGED] 
         4  [CHANGED] def new_function():
         5  [CHANGED]     return "new"

    This gives the model a strong visual anchor for what to focus on.
    """
    if not content:
        return ""

    lines = content.splitlines()

    # Build a set of changed line numbers for O(1) lookup
    changed_lines: set[int] = set()
    for start, end in changed_ranges:
        changed_lines.update(range(start, end + 1))

    # Format each line with its number and marker
    width = len(str(len(lines)))
    marked_lines: list[str] = []
    for i, line in enumerate(lines, start=1):
        marker = "[CHANGED]" if i in changed_lines else "[CONTEXT]"
        marked_lines.append(f"{i:>{width}}  {marker} {line}")

    return "\n".join(marked_lines)


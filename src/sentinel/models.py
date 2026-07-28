"""
Pydantic data models for Sentinel Review.

These models define the data contract for the entire package:
    - Finding: a single security vulnerability discovered in code
    - ReviewResult: the full output of a code review (findings + metadata)
    - Severity, Confidence: enums used inside Finding

The same schema is mirrored in analyzer.py as a JSON Schema tool definition
for the Anthropic API. If you change a field here, update the tool schema too.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """
    Severity levels for a finding.

    Inherits from str so values serialize cleanly to JSON ("high" not
    "Severity.HIGH") and so comparisons against string literals work.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric ordering for sorting and threshold comparisons."""
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


class Confidence(str, Enum):
    """How confident the reviewer is that a finding is a real vulnerability."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Language(str, Enum):
    """
    Supported programming languages for security analysis.

    Each language corresponds to a specific system prompt module in
    sentinel.prompts. Adding a new language requires:
      1. Adding an entry here
      2. Creating a prompt module under sentinel.prompts.<language>
      3. Registering the file extension in sentinel.diff.language_detection
      4. Adding a corpus under examples/vulnerable_samples/<language>/
    """

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"

    @property
    def display_name(self) -> str:
        """Human-readable name for use in output and error messages."""
        return {
            Language.PYTHON: "Python",
            Language.JAVASCRIPT: "JavaScript",
            Language.TYPESCRIPT: "TypeScript",
        }[self]

    @property
    def file_extensions(self) -> tuple[str, ...]:
        """File extensions associated with this language, lowercase, with the leading dot."""
        return {
            Language.PYTHON: (".py",),
            Language.JAVASCRIPT: (".js", ".jsx", ".mjs", ".cjs"),
            Language.TYPESCRIPT: (".ts", ".tsx"),
        }[self]

# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """
    A single security vulnerability discovered during review.

    This is the core unit of output. Every detection produced by the analyzer
    is represented as one Finding. Findings should be self-contained: a
    developer reading just one Finding should be able to understand the
    problem, locate it, and fix it without referring back to the full report.
    """

    model_config = ConfigDict(
        # Allow Severity("high") to be constructed from the string "high"
        use_enum_values=False,
        # Reject unexpected fields - if the model invents a new field, we want
        # to know about it during parsing rather than silently dropping it.
        extra="forbid",
        # Frozen findings - once created, they shouldn't be mutated.
        frozen=True,
    )

    severity: Severity = Field(
        ...,
        description="Severity of the vulnerability.",
    )
    cwe_id: str = Field(
        ...,
        description="CWE identifier, e.g. 'CWE-89' for SQL injection.",
        pattern=r"^CWE-\d+$",
    )
    owasp_category: str = Field(
        ...,
        description="OWASP Top 10 category, e.g. 'A03:2021 - Injection'.",
        min_length=1,
    )
    title: str = Field(
        ...,
        description="Short title summarizing the finding.",
        min_length=1,
        max_length=200,
    )
    file_path: str = Field(
        ...,
        description="Path of the file containing the finding.",
        min_length=1,
    )
    line_start: int = Field(
        ...,
        description="First line of the vulnerable code (1-indexed).",
        ge=1,
    )
    line_end: int = Field(
        ...,
        description="Last line of the vulnerable code (1-indexed, inclusive).",
        ge=1,
    )
    description: str = Field(
        ...,
        description="Detailed explanation of the vulnerability.",
        min_length=1,
    )
    vulnerable_code: str = Field(
        ...,
        description="The exact code snippet that is vulnerable.",
    )
    suggested_fix: str = Field(
        ...,
        description="Concrete remediation, ideally with example code.",
        min_length=1,
    )
    confidence: Confidence = Field(
        ...,
        description="Reviewer confidence that this is a real vulnerability.",
    )
    reasoning: str = Field(
        ...,
        description="Why this is considered a vulnerability. Used for "
                    "explainability and developer education.",
        min_length=1,
    )

    @model_validator(mode="after")
    def _validate_line_range(self) -> Self:
        """line_end must be greater than or equal to line_start."""
        if self.line_end < self.line_start:
            raise ValueError(
                f"line_end ({self.line_end}) must be >= "
                f"line_start ({self.line_start})"
            )
        return self


# ---------------------------------------------------------------------------
# ReviewResult
# ---------------------------------------------------------------------------

class ReviewResult(BaseModel):
    """
    The complete output of a code review.

    Contains the list of findings, the files that were analyzed, an overall
    summary, and metadata about the API call (model, tokens, latency, cost).
    The metadata fields power the benchmarks in Phase 4.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings discovered during review.",
    )
    files_analyzed: list[str] = Field(
        default_factory=list,
        description="List of file paths that were analyzed in this review.",
    )
    summary: str = Field(
        default="",
        description="Brief overall summary of the review.",
    )

    # ----- Metadata -----------------------------------------------------

    model: str = Field(
        ...,
        description="Anthropic model used for the review, e.g. 'claude-sonnet-4-5'.",
    )
    input_tokens: int = Field(
        default=0,
        ge=0,
        description="Number of input tokens consumed.",
    )
    output_tokens: int = Field(
        default=0,
        ge=0,
        description="Number of output tokens generated.",
    )
    language: Language | None = Field(
        default=None,
        description=(
            "Language of the analyzed code. Optional for backward compatibility "
            "with Phase 1 reviews and multi-language directory scans."
        ),
    )
    elapsed_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Wall-clock time the API call took.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the review was completed (UTC).",
    )

    # ----- Convenience properties --------------------------------------

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        """True if at least one finding was reported."""
        return bool(self.findings)

    @property
    def highest_severity(self) -> Severity | None:
        """Highest severity across all findings, or None if there are none."""
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank).severity

    def findings_at_or_above(self, threshold: Severity) -> list[Finding]:
        """Return findings whose severity meets or exceeds the threshold."""
        return [f for f in self.findings if f.severity >= threshold]

    def count_by_severity(self) -> dict[Severity, int]:
        """Histogram of findings by severity."""
        counts: dict[Severity, int] = {sev: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts
    
# ---------------------------------------------------------------------------
# DiffFile (Phase 2)
# ---------------------------------------------------------------------------

class DiffFile(BaseModel):
    """
    Represents a single file changed in a pull request diff.

    Produced by the diff parser and consumed by the analyzer. Contains the
    file's full new content (so the model has context) and metadata about
    which lines actually changed (so the analyzer can focus its review).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: str = Field(
        ...,
        description="Path of the file relative to the repo root.",
        min_length=1,
    )
    new_content: str = Field(
        ...,
        description="Full content of the file after the change.",
    )
    changed_line_ranges: list[tuple[int, int]] = Field(
        default_factory=list,
        description=(
            "List of (start, end) line-range tuples marking which lines "
            "were added or modified. Line numbers refer to the new_content. "
            "Ranges are inclusive on both ends and 1-indexed."
        ),
    )
    is_new_file: bool = Field(
        default=False,
        description="True if this file did not exist before the PR.",
    )

    language: Language = Field(
        ...,
        description="Programming language of this file, used to route to the correct prompt.",
    )
    
    @model_validator(mode="after")
    def _validate_line_ranges(self) -> Self:
        """All ranges must be valid (start <= end, both >= 1)."""
        for i, (start, end) in enumerate(self.changed_line_ranges):
            if start < 1:
                raise ValueError(
                    f"changed_line_ranges[{i}]: start ({start}) must be >= 1"
                )
            if end < start:
                raise ValueError(
                    f"changed_line_ranges[{i}]: end ({end}) must be >= start ({start})"
                )
        return self

    @property
    def is_pure_addition(self) -> bool:
        """True if this file was newly created in this PR."""
        return self.is_new_file

    @property
    def total_changed_lines(self) -> int:
        """Total count of changed lines across all ranges."""
        return sum(end - start + 1 for start, end in self.changed_line_ranges)

    def contains_line(self, line_number: int) -> bool:
        """Check if a given line number falls within any changed range."""
        return any(
            start <= line_number <= end
            for start, end in self.changed_line_ranges
        )
"""
Prompts package.

Contains the system prompts for security code review, organized by language.
This module re-exports the Python prompt content for backward compatibility
with Phase 1 code paths.
"""

from sentinel.prompts.python import (
    SECURITY_REVIEW_SYSTEM_PROMPT,
    FEW_SHOT_EXAMPLES,
    SYSTEM_PROMPT_VERSION,
    format_review_request,
    _add_line_numbers,
)

__all__ = [
    "SECURITY_REVIEW_SYSTEM_PROMPT",
    "FEW_SHOT_EXAMPLES",
    "SYSTEM_PROMPT_VERSION",
    "format_review_request",
    "_add_line_numbers",
]
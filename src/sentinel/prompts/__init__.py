"""
Prompts package.

Provides language-aware prompt routing. The main entry point is
get_prompt_module(language), which returns the module for a given
Language enum value. Callers extract SECURITY_REVIEW_SYSTEM_PROMPT,
format_review_request, and other names from that module.

Backward compatibility: the direct re-exports at the bottom of this file
preserve the Phase 1 import path (`from sentinel.prompts import
SECURITY_REVIEW_SYSTEM_PROMPT`). This is intentional so that Phase 1
callers keep working during the Phase 2 transition. New code should
use get_prompt_module() to make the language explicit.
"""

from __future__ import annotations

from types import ModuleType

from sentinel.models import Language
from sentinel.prompts import python as python_module

# Map from Language enum to the corresponding prompt module.
# Add new entries here as new languages are supported.
_LANGUAGE_MODULES: dict[Language, ModuleType] = {
    Language.PYTHON: python_module,
    # Language.JAVASCRIPT: javascript_module,  # Uncomment in Phase 2 item 30
    # Language.TYPESCRIPT: javascript_module,  # Shares JS prompt
}


def get_prompt_module(language: Language) -> ModuleType:
    """
    Return the prompt module for a given language.

    Callers use this to access language-specific constants and functions:

        from sentinel.prompts import get_prompt_module
        module = get_prompt_module(Language.PYTHON)
        prompt = module.SECURITY_REVIEW_SYSTEM_PROMPT

    Args:
        language: The Language enum value.

    Returns:
        The Python module containing that language's prompt content.

    Raises:
        ValueError: If the language is not yet supported.
    """
    if language not in _LANGUAGE_MODULES:
        supported = ", ".join(l.value for l in _LANGUAGE_MODULES)
        raise ValueError(
            f"No prompt module for language '{language.value}'. "
            f"Supported: {supported}"
        )
    return _LANGUAGE_MODULES[language]


def supported_languages() -> set[Language]:
    """
    Return the set of languages with prompt modules registered.

    Useful for CLI help text and for the analyzer to check whether a
    given file's language is analyzable.
    """
    return set(_LANGUAGE_MODULES.keys())


# ---------------------------------------------------------------------------
# Backward-compat re-exports (Phase 1 compatibility)
# ---------------------------------------------------------------------------
# These names existed at the package level in Phase 1. Keeping them here
# means existing code paths (analyzer.py, test files) don't need to change
# during the Phase 2 refactor. New code should use get_prompt_module().

from sentinel.prompts.python import (
    SECURITY_REVIEW_SYSTEM_PROMPT,
    FEW_SHOT_EXAMPLES,
    SYSTEM_PROMPT_VERSION,
    format_review_request,
    _add_line_numbers,
)

__all__ = [
    # New language-aware API (preferred for Phase 2+)
    "get_prompt_module",
    "supported_languages",
    # Phase 1 backward-compat exports (default to Python)
    "SECURITY_REVIEW_SYSTEM_PROMPT",
    "FEW_SHOT_EXAMPLES",
    "SYSTEM_PROMPT_VERSION",
    "format_review_request",
    "_add_line_numbers",
]
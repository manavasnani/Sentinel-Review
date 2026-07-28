"""Diff parsing and analysis utilities for Phase 2."""

from sentinel.diff.language_detection import (
    detect_language,
    is_supported,
    supported_extensions,
)

__all__ = [
    "detect_language",
    "is_supported",
    "supported_extensions",
]
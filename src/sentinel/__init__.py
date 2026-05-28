"""
Sentinel Review - AI-powered secure code review.

An LLM-based static analysis tool that complements traditional SAST by reasoning
about code intent and context to detect vulnerabilities that pattern-matching
tools miss.
"""

from sentinel.analyzer import analyze_code, analyze_file
from sentinel.exceptions import (
    AnalysisError,
    APIError,
    ConfigurationError,
    ParseError,
    SentinelError,
)
from sentinel.models import Confidence, Finding, ReviewResult, Severity

__version__ = "0.1.0"
__author__ = "Manav Asnani"
__license__ = "MIT"

__all__ = [
    "__version__",
    "analyze_file",
    "analyze_code",
    "Finding",
    "ReviewResult",
    "Severity",
    "Confidence",
    "SentinelError",
    "APIError",
    "ParseError",
    "ConfigurationError",
    "AnalysisError",
]
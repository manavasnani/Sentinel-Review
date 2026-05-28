"""
Custom exceptions for Sentinel Review.

All exceptions raised by the sentinel package inherit from SentinelError,
so callers can catch everything with a single except clause if they want,
or catch specific subclasses for fine-grained handling.
"""

from __future__ import annotations


class SentinelError(Exception):
    """
    Base class for all Sentinel exceptions.

    Catch this if you want to handle any error from the sentinel package
    without caring about the specific cause.
    """


class ConfigurationError(SentinelError):
    """
    Raised when the package is misconfigured.

    Examples:
        - ANTHROPIC_API_KEY is missing or empty
        - An invalid model name is specified
        - A required environment variable is not set
    """


class APIError(SentinelError):
    """
    Raised when the Anthropic API call fails in a non-recoverable way.

    This wraps underlying anthropic SDK errors after retries have been
    exhausted, or for errors that aren't worth retrying (auth failures,
    malformed requests, etc.).
    """


class ParseError(SentinelError):
    """
    Raised when the API response cannot be parsed into the expected schema.

    This usually means:
        - The model returned a response without the expected tool_use block
        - The tool input failed Pydantic validation in an unrecoverable way
        - The API response shape changed unexpectedly
    """


class AnalysisError(SentinelError):
    """
    Raised when analysis cannot proceed for reasons unrelated to the API.

    Examples:
        - The file to analyze does not exist
        - The file is not readable as UTF-8 (binary file)
        - The file is empty or exceeds size limits
    """
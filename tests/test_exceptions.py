"""Tests for the custom exception hierarchy."""

import pytest

from sentinel.exceptions import (
    AnalysisError,
    APIError,
    ConfigurationError,
    ParseError,
    SentinelError,
)


@pytest.mark.parametrize(
    "exc_class",
    [ConfigurationError, APIError, ParseError, AnalysisError],
)
def test_all_exceptions_inherit_from_sentinel_error(exc_class):
    """Every custom exception should be catchable as SentinelError."""
    with pytest.raises(SentinelError):
        raise exc_class("test message")


def test_exceptions_preserve_message():
    """Exception messages should round-trip through str()."""
    msg = "API key is not set"
    exc = ConfigurationError(msg)
    assert str(exc) == msg


def test_exception_chaining():
    """The `from` clause should preserve the original cause."""
    original = ValueError("bad value")
    try:
        try:
            raise original
        except ValueError as e:
            raise APIError("wrapped") from e
    except APIError as wrapped:
        assert wrapped.__cause__ is original

"""
Configuration for Sentinel Review.

Loads settings from environment variables (with .env file support) and provides
a typed config object the rest of the package can depend on. Centralizing this
here means no other module needs to call os.getenv directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Final

from dotenv import load_dotenv

from sentinel.exceptions import ConfigurationError


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_MODEL: Final[str] = "claude-sonnet-4-6"
DEFAULT_MAX_TOKENS: Final[int] = 4096
DEFAULT_TEMPERATURE: Final[float] = 0.0
DEFAULT_MAX_RETRIES: Final[int] = 4
DEFAULT_INITIAL_RETRY_DELAY: Final[float] = 1.0
DEFAULT_REQUEST_TIMEOUT: Final[float] = 120.0
DEFAULT_LOG_LEVEL: Final[str] = "INFO"

ALLOWED_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)


# ---------------------------------------------------------------------------
# Config object
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SentinelConfig:
    """
    Runtime configuration for the analyzer.

    Frozen so it can't be accidentally mutated mid-run. To override a value,
    construct a new SentinelConfig (or use dataclasses.replace).
    """

    api_key: str = field(repr=False)  # repr=False so it never appears in logs
    model: str = DEFAULT_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    max_retries: int = DEFAULT_MAX_RETRIES
    initial_retry_delay: float = DEFAULT_INITIAL_RETRY_DELAY
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    log_level: str = DEFAULT_LOG_LEVEL

    def __post_init__(self) -> None:
        """Validate values after construction."""
        if not self.api_key:
            raise ConfigurationError(
                "ANTHROPIC_API_KEY is required. Set it in your environment "
                "or in a .env file at the project root."
            )
        if not self.model:
            raise ConfigurationError("model must not be empty.")
        if self.max_tokens < 1:
            raise ConfigurationError(
                f"max_tokens must be >= 1 (got {self.max_tokens})."
            )
        if not 0.0 <= self.temperature <= 1.0:
            raise ConfigurationError(
                f"temperature must be between 0.0 and 1.0 (got {self.temperature})."
            )
        if self.max_retries < 0:
            raise ConfigurationError(
                f"max_retries must be >= 0 (got {self.max_retries})."
            )
        if self.initial_retry_delay < 0:
            raise ConfigurationError(
                f"initial_retry_delay must be >= 0 (got {self.initial_retry_delay})."
            )
        if self.request_timeout <= 0:
            raise ConfigurationError(
                f"request_timeout must be > 0 (got {self.request_timeout})."
            )
        if self.log_level.upper() not in ALLOWED_LOG_LEVELS:
            raise ConfigurationError(
                f"log_level must be one of {sorted(ALLOWED_LOG_LEVELS)} "
                f"(got {self.log_level!r})."
            )


# ---------------------------------------------------------------------------
# Environment loading
# ---------------------------------------------------------------------------

def _env_str(name: str, default: str) -> str:
    """Read a string env var, falling back to default if unset or empty."""
    value = os.getenv(name)
    return value if value else default


def _env_int(name: str, default: int) -> int:
    """Read an integer env var. Raises ConfigurationError on invalid input."""
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError as e:
        raise ConfigurationError(
            f"Environment variable {name} must be an integer (got {value!r})."
        ) from e


def _env_float(name: str, default: float) -> float:
    """Read a float env var. Raises ConfigurationError on invalid input."""
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except ValueError as e:
        raise ConfigurationError(
            f"Environment variable {name} must be a number (got {value!r})."
        ) from e


def get_config() -> SentinelConfig:
    """
    Build a SentinelConfig from environment variables.

    Reads the following env vars (all optional except ANTHROPIC_API_KEY):
        ANTHROPIC_API_KEY        - your Anthropic API key (required)
        SENTINEL_MODEL           - Claude model to use
        SENTINEL_MAX_TOKENS      - max tokens in the response
        SENTINEL_TEMPERATURE     - sampling temperature (0.0 to 1.0)
        SENTINEL_MAX_RETRIES     - retry attempts on transient errors
        SENTINEL_RETRY_DELAY     - initial backoff delay in seconds
        SENTINEL_TIMEOUT         - per-request timeout in seconds
        SENTINEL_LOG_LEVEL       - DEBUG, INFO, WARNING, ERROR, or CRITICAL

    If a .env file exists at the project root, it is loaded first.
    """
    # load_dotenv silently does nothing if .env doesn't exist, which is fine.
    # Real environment variables take precedence over .env contents.
    load_dotenv(override=False)

    return SentinelConfig(
        api_key=_env_str("ANTHROPIC_API_KEY", ""),
        model=_env_str("SENTINEL_MODEL", DEFAULT_MODEL),
        max_tokens=_env_int("SENTINEL_MAX_TOKENS", DEFAULT_MAX_TOKENS),
        temperature=_env_float("SENTINEL_TEMPERATURE", DEFAULT_TEMPERATURE),
        max_retries=_env_int("SENTINEL_MAX_RETRIES", DEFAULT_MAX_RETRIES),
        initial_retry_delay=_env_float(
            "SENTINEL_RETRY_DELAY", DEFAULT_INITIAL_RETRY_DELAY
        ),
        request_timeout=_env_float("SENTINEL_TIMEOUT", DEFAULT_REQUEST_TIMEOUT),
        log_level=_env_str("SENTINEL_LOG_LEVEL", DEFAULT_LOG_LEVEL).upper(),
    )
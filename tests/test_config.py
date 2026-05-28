"""Tests for the configuration module."""

import pytest

from sentinel.config import (
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    SentinelConfig,
    get_config,
)
from sentinel.exceptions import ConfigurationError


class TestSentinelConfig:
    def test_valid_config(self):
        c = SentinelConfig(api_key="sk-test")
        assert c.model == DEFAULT_MODEL
        assert c.temperature == DEFAULT_TEMPERATURE

    def test_empty_api_key_rejected(self):
        with pytest.raises(ConfigurationError, match="API_KEY"):
            SentinelConfig(api_key="")

    def test_invalid_temperature_rejected(self):
        with pytest.raises(ConfigurationError, match="temperature"):
            SentinelConfig(api_key="sk-test", temperature=2.0)

    def test_negative_max_tokens_rejected(self):
        with pytest.raises(ConfigurationError, match="max_tokens"):
            SentinelConfig(api_key="sk-test", max_tokens=0)

    def test_invalid_log_level_rejected(self):
        with pytest.raises(ConfigurationError, match="log_level"):
            SentinelConfig(api_key="sk-test", log_level="VERBOSE")

    def test_api_key_not_in_repr(self):
        """Critical security check: API key must not appear in repr."""
        c = SentinelConfig(api_key="sk-supersecret-12345")
        assert "supersecret" not in repr(c)
        assert "sk-" not in repr(c)

    def test_config_is_frozen(self):
        c = SentinelConfig(api_key="sk-test")
        with pytest.raises(Exception):  # FrozenInstanceError
            c.model = "different-model"  # type: ignore[misc]


class TestGetConfig:
    def test_reads_env_vars(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("SENTINEL_MODEL", "claude-opus-4-7")
        monkeypatch.setenv("SENTINEL_TEMPERATURE", "0.2")

        c = get_config()
        assert c.api_key == "sk-test"
        assert c.model == "claude-opus-4-7"
        assert c.temperature == 0.2

    def test_normalizes_log_level_case(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("SENTINEL_LOG_LEVEL", "debug")
        c = get_config()
        assert c.log_level == "DEBUG"

    def test_invalid_int_env_var_raises(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("SENTINEL_MAX_TOKENS", "not-a-number")
        with pytest.raises(ConfigurationError, match="MAX_TOKENS"):
            get_config()

    def test_missing_api_key_raises(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ConfigurationError, match="API_KEY"):
            get_config()

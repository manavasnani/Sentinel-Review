"""Tests for GitHub event parser."""

import json
from pathlib import Path

import pytest

from sentinel.exceptions import ConfigurationError
from sentinel.github.event_parser import PRContext, parse_event


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "github_events"


class TestPRContext:
    def test_full_repo(self):
        ctx = PRContext(
            owner="manavasnani",
            repo="Sentinel-Review",
            pr_number=42,
            head_sha="abc123def456",
            base_sha="111222333444",
        )
        assert ctx.full_repo == "manavasnani/Sentinel-Review"

    def test_frozen(self):
        ctx = PRContext(
            owner="x", repo="y", pr_number=1,
            head_sha="a", base_sha="b",
        )
        with pytest.raises(AttributeError):
            ctx.owner = "z"


class TestParseEvent:
    def test_missing_event_path_raises(self, monkeypatch):
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
        with pytest.raises(ConfigurationError, match="GITHUB_EVENT_PATH"):
            parse_event()

    def test_missing_file_raises(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(tmp_path / "nope.json"))
        with pytest.raises(ConfigurationError, match="not found"):
            parse_event()

    def test_invalid_json_raises(self, monkeypatch, tmp_path):
        bad_file = tmp_path / "event.json"
        bad_file.write_text("not json", encoding="utf-8")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(bad_file))
        with pytest.raises(ConfigurationError, match="parse"):
            parse_event()

    def test_missing_pull_request_raises(self, monkeypatch, tmp_path):
        event_file = tmp_path / "event.json"
        event_file.write_text(json.dumps({"action": "push"}), encoding="utf-8")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
        monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
        with pytest.raises(ConfigurationError, match="pull_request"):
            parse_event()

    def test_valid_event_parses(self, monkeypatch, tmp_path):
        event = {
            "action": "opened",
            "pull_request": {
                "number": 42,
                "head": {"sha": "abc123"},
                "base": {"sha": "def456"},
            },
        }
        event_file = tmp_path / "event.json"
        event_file.write_text(json.dumps(event), encoding="utf-8")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
        monkeypatch.setenv("GITHUB_REPOSITORY", "manavasnani/Sentinel-Review")

        ctx = parse_event()
        assert ctx.owner == "manavasnani"
        assert ctx.repo == "Sentinel-Review"
        assert ctx.pr_number == 42
        assert ctx.head_sha == "abc123"
        assert ctx.base_sha == "def456"

    def test_missing_github_repository_raises(self, monkeypatch, tmp_path):
        event = {
            "pull_request": {
                "number": 1,
                "head": {"sha": "a"},
                "base": {"sha": "b"},
            },
        }
        event_file = tmp_path / "event.json"
        event_file.write_text(json.dumps(event), encoding="utf-8")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        with pytest.raises(ConfigurationError, match="GITHUB_REPOSITORY"):
            parse_event()
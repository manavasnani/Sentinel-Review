"""
Parse GitHub Actions event payloads.

When a GitHub Action runs, the event that triggered it is written to a JSON
file at the path specified by the GITHUB_EVENT_PATH environment variable.
This module reads that file and extracts the fields Sentinel needs: the
repository, PR number, and the head/base commit SHAs.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from sentinel.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PRContext:
    """
    Minimal context needed to review a pull request.

    Extracted from the GitHub event payload and environment variables.
    All fields are required for the Action to function.
    """

    owner: str
    repo: str
    pr_number: int
    head_sha: str
    base_sha: str

    @property
    def full_repo(self) -> str:
        """owner/repo format used by the GitHub API."""
        return f"{self.owner}/{self.repo}"


def parse_event() -> PRContext:
    """
    Read the GitHub Actions event payload and extract PR context.

    Reads from GITHUB_EVENT_PATH (set by the Actions runner) and
    GITHUB_REPOSITORY (owner/repo). Raises ConfigurationError if
    required fields are missing.

    Returns:
        PRContext with all fields populated.

    Raises:
        ConfigurationError: If environment variables or event fields
                            are missing.
    """
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        raise ConfigurationError(
            "GITHUB_EVENT_PATH is not set. "
            "This module must run inside a GitHub Actions workflow."
        )

    event_file = Path(event_path)
    if not event_file.exists():
        raise ConfigurationError(
            f"Event file not found at {event_path}. "
            "The Actions runner should have created this file."
        )

    try:
        event = json.loads(event_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ConfigurationError(
            f"Failed to parse event file at {event_path}: {e}"
        ) from e

    # Extract the PR object from the event
    pull_request = event.get("pull_request")
    if not pull_request:
        raise ConfigurationError(
            "Event payload does not contain a 'pull_request' field. "
            "Sentinel only supports pull_request events. "
            "Check your workflow trigger configuration."
        )

    pr_number = pull_request.get("number")
    if not pr_number:
        raise ConfigurationError("PR number is missing from the event payload.")

    head_sha = pull_request.get("head", {}).get("sha")
    if not head_sha:
        raise ConfigurationError("Head SHA is missing from the event payload.")

    base_sha = pull_request.get("base", {}).get("sha")
    if not base_sha:
        raise ConfigurationError("Base SHA is missing from the event payload.")

    # GITHUB_REPOSITORY is "owner/repo"
    full_repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in full_repo:
        raise ConfigurationError(
            f"GITHUB_REPOSITORY is not set or invalid: {full_repo!r}. "
            "Expected format: 'owner/repo'."
        )

    owner, repo = full_repo.split("/", 1)

    logger.info(
        "Parsed PR context: %s/%s #%d (base=%s, head=%s)",
        owner,
        repo,
        pr_number,
        base_sha[:7],
        head_sha[:7],
    )

    return PRContext(
        owner=owner,
        repo=repo,
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
    )
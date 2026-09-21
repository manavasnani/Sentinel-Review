"""
GitHub REST API client for pull request operations.

Handles two things:
  1. Fetching the unified diff for a pull request
  2. Posting a review with inline comments on specific lines

Uses PyGithub for the review submission (which requires structured API
calls) and raw requests for the diff (which needs the Accept header set
to get the unified diff format).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

import requests
from github import Github
from github.GithubException import GithubException

from sentinel.exceptions import APIError
from sentinel.github.event_parser import PRContext
from sentinel.models import Finding, ReviewResult

logger = logging.getLogger(__name__)


def _get_github_token() -> str:
    """Read the GitHub token from the environment."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB_TOKEN")
    if not token:
        raise APIError(
            "No GitHub token found. Set GITHUB_TOKEN or pass it as an input "
            "to the Action."
        )
    return token


def fetch_pr_diff(context: PRContext) -> str:
    """
    Fetch the unified diff for a pull request via the GitHub REST API.

    Uses the raw requests library instead of PyGithub because PyGithub
    doesn't support the Accept header needed to get the diff format.

    Args:
        context: PR context with owner, repo, and PR number.

    Returns:
        The unified diff as a string.

    Raises:
        APIError: If the API call fails.
    """
    token = _get_github_token()
    url = (
        f"https://api.github.com/repos/{context.full_repo}"
        f"/pulls/{context.pr_number}"
    )

    try:
        response = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3.diff",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise APIError(
            f"Failed to fetch PR diff from {url}: {e}"
        ) from e

    diff_text = response.text
    logger.info(
        "Fetched diff for %s #%d: %d bytes",
        context.full_repo,
        context.pr_number,
        len(diff_text),
    )
    return diff_text


@dataclass
class ReviewComment:
    """A single inline comment to post on a PR."""

    path: str
    line: int
    body: str
    side: str = "RIGHT"


def post_review(
    context: PRContext,
    results: list[ReviewResult],
    comment_body: str,
    comments: list[ReviewComment],
) -> None:
    """
    Post a review on the pull request with inline comments.

    Uses PyGithub to create a PR review, which bundles the top-level
    summary comment with all inline comments in a single API call.

    Args:
        context: PR context.
        results: The ReviewResult objects (used for metadata).
        comment_body: The top-level review summary.
        comments: List of inline comments to attach to specific lines.

    Raises:
        APIError: If the GitHub API call fails.
    """
    token = _get_github_token()
    gh = Github(token)

    try:
        repo = gh.get_repo(context.full_repo)
        pr = repo.get_pull(context.pr_number)

        # Build the PyGithub comment objects
        review_comments = []
        for comment in comments:
            review_comments.append({
                "path": comment.path.replace("\\", "/"),
                "line": comment.line,
                "side": comment.side,
                "body": comment.body,
            })

        # Determine the review event type
        total_findings = sum(len(r.findings) for r in results)
        event = "COMMENT"  # neutral review, doesn't approve or request changes

        pr.create_review(
            commit=repo.get_commit(context.head_sha),
            body=comment_body,
            event=event,
            comments=review_comments,
        )

        logger.info(
            "Posted review on %s #%d: %d inline comments, %d total findings",
            context.full_repo,
            context.pr_number,
            len(review_comments),
            total_findings,
        )

    except GithubException as e:
        raise APIError(
            f"Failed to post review on {context.full_repo} #{context.pr_number}: "
            f"{e.status} {e.data}"
        ) from e
    finally:
        gh.close()
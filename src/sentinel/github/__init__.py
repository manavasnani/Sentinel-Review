"""GitHub Action integration for Sentinel Review."""

from sentinel.github.action import run
from sentinel.github.event_parser import PRContext, parse_event
from sentinel.github.pr_client import fetch_pr_diff, post_review
from sentinel.github.comment_formatter import (
    findings_to_review_comments,
    format_finding_comment,
    format_review_summary,
)

__all__ = [
    "run",
    "PRContext",
    "parse_event",
    "fetch_pr_diff",
    "post_review",
    "findings_to_review_comments",
    "format_finding_comment",
    "format_review_summary",
]
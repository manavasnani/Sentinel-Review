"""
Main entry point for the Sentinel Review GitHub Action.

Orchestrates the full PR review flow:
  1. Parse the GitHub event to get PR context
  2. Fetch the PR diff via the GitHub API
  3. Parse the diff into reviewable files
  4. Analyze each file with the language-specific prompt
  5. Format findings as PR review comments
  6. Post the review on the PR

This module is invoked by the Dockerfile's ENTRYPOINT.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from sentinel.analyzer import analyze_diff_file
from sentinel.config import get_config
from sentinel.diff.parser import parse_diff
from sentinel.exceptions import SentinelError
from sentinel.github.comment_formatter import (
    findings_to_review_comments,
    format_review_summary,
)
from sentinel.github.event_parser import parse_event
from sentinel.github.pr_client import fetch_pr_diff, post_review
from sentinel.models import ReviewResult, Severity

logger = logging.getLogger(__name__)


def run() -> int:
    """
    Execute the full PR review workflow.

    Returns:
        Exit code: 0 if no findings above threshold, 1 if findings
        exceed threshold, 2 for configuration errors.
    """
    # Set up logging
    log_level = os.environ.get("INPUT_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        # Step 1: Parse event
        logger.info("Parsing GitHub event...")
        context = parse_event()

        # Step 2: Fetch diff
        logger.info("Fetching PR diff for %s #%d...", context.full_repo, context.pr_number)
        diff_text = fetch_pr_diff(context)

        # Step 3: Parse diff
        diff_files = parse_diff(diff_text)
        if not diff_files:
            logger.info("No reviewable files in this PR. Skipping analysis.")
            return 0

        logger.info("Found %d reviewable file(s) in the diff.", len(diff_files))

        # Step 4: Analyze each file
        config = get_config()
        results: list[ReviewResult] = []

        for df in diff_files:
            logger.info(
                "Analyzing %s (%s, %d changed lines)...",
                df.file_path,
                df.language.display_name,
                df.total_changed_lines,
            )
            result = analyze_diff_file(df, config=config)
            results.append(result)
            logger.info(
                "  -> %d finding(s) in %s",
                len(result.findings),
                df.file_path,
            )

        # Step 5: Format comments
        total_findings = sum(len(r.findings) for r in results)
        logger.info("Analysis complete. %d total finding(s).", total_findings)

        review_body = format_review_summary(results)
        review_comments = findings_to_review_comments(results)

        # Step 6: Post review
        if os.environ.get("INPUT_DRY_RUN", "false").lower() == "true":
            logger.info("Dry run mode. Skipping review post.")
            logger.info("Review body:\n%s", review_body)
            for c in review_comments:
                logger.info("Comment on %s:%d:\n%s", c.path, c.line, c.body)
        else:
            logger.info("Posting review with %d inline comments...", len(review_comments))
            post_review(context, results, review_body, review_comments)
            logger.info("Review posted successfully.")
            
        # Step 6.5: Write SARIF output if requested
        sarif_file = os.environ.get("INPUT_SARIF_FILE", "")
        if sarif_file:
            from sentinel.sarif.converter import results_to_sarif_json
            sarif_json = results_to_sarif_json(results)
            sarif_path = Path(sarif_file)
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            sarif_path.write_text(sarif_json, encoding="utf-8")
            logger.info("Wrote SARIF output to %s", sarif_path)

        # Step 7: Determine exit code based on threshold
        fail_on = os.environ.get("INPUT_FAIL_ON", "").lower()
        if fail_on:
            try:
                threshold = Severity(fail_on)
            except ValueError:
                logger.warning("Invalid fail_on severity: %s. Ignoring.", fail_on)
                return 0

            for result in results:
                if result.findings_at_or_above(threshold):
                    logger.info(
                        "Findings at or above %s severity found. Failing.",
                        threshold.value,
                    )
                    return 1

        return 0

    except SentinelError as e:
        logger.error("Sentinel error: %s", e)
        return 2
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        return 2


def main() -> None:
    """CLI entry point for the Action container."""
    sys.exit(run())


if __name__ == "__main__":
    main()
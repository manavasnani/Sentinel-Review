"""
Git diff parser.

Takes a unified diff string (from `git diff` or the GitHub API) and returns
structured DiffFile objects. Each DiffFile represents one changed file with:
    - path (str)
    - full new content (str) — reconstructed from the diff
    - changed line ranges [(start, end), ...] — lines added or modified
    - language (from file extension)
    - is_new_file flag

Uses the `unidiff` library for the low-level parsing. This module handles
the semantic interpretation: extracting language, computing line ranges,
filtering to supported languages.
"""

from __future__ import annotations

import logging
from pathlib import Path

from unidiff import PatchSet
from unidiff.patch import PatchedFile

from sentinel.diff.language_detection import detect_language, is_supported
from sentinel.exceptions import AnalysisError
from sentinel.models import DiffFile, Language

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_diff(diff_text: str) -> list[DiffFile]:
    """
    Parse a unified diff string into DiffFile objects.

    Filters out deleted files (nothing to review), binary files, and files
    whose language is not supported.

    Args:
        diff_text: Raw unified diff text. Typically from `git diff` output
                   or the GitHub API's PR files endpoint.

    Returns:
        List of DiffFile objects, one per reviewable changed file.
        Empty list if no reviewable files are present in the diff.

    Raises:
        AnalysisError: If the diff text is malformed and cannot be parsed.
    """
    if not diff_text or not diff_text.strip():
        return []

    try:
        patch_set = PatchSet(diff_text)
    except Exception as e:
        raise AnalysisError(f"Failed to parse diff: {e}") from e

    diff_files: list[DiffFile] = []

    for patched_file in patch_set:
        result = _process_patched_file(patched_file)
        if result is not None:
            diff_files.append(result)

    return diff_files


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _process_patched_file(patched_file: PatchedFile) -> DiffFile | None:
    """
    Convert one unidiff PatchedFile into a DiffFile, or None if it should
    be skipped.

    Skip conditions:
      - Deleted files (nothing to review)
      - Binary files (can't analyze)
      - Unsupported languages (e.g., .md, .json, .yaml)
    """
    file_path = _resolve_file_path(patched_file)

    if patched_file.is_removed_file:
        logger.debug("Skipping deleted file: %s", file_path)
        return None

    if patched_file.is_binary_file:
        logger.debug("Skipping binary file: %s", file_path)
        return None

    if not is_supported(file_path):
        logger.debug("Skipping unsupported language: %s", file_path)
        return None

    language = detect_language(file_path)
    if language is None:
        # Guarded by is_supported() above, but defensive
        return None

    changed_line_ranges = _extract_changed_line_ranges(patched_file)
    new_content = _reconstruct_new_content(patched_file)
    is_new_file = patched_file.is_added_file

    return DiffFile(
        file_path=file_path,
        new_content=new_content,
        changed_line_ranges=changed_line_ranges,
        is_new_file=is_new_file,
        language=language,
    )


def _resolve_file_path(patched_file: PatchedFile) -> str:
    """
    Determine the canonical file path for this diff entry.

    For most changes we use the new path (target_file). For deleted files
    we'd use the old path, but we skip those anyway.

    Strips the leading 'a/' or 'b/' git prefix that unidiff sometimes
    preserves.
    """
    path = patched_file.target_file or patched_file.source_file or ""

    # Strip git's a/ and b/ prefixes
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]

    return path


def _extract_changed_line_ranges(
    patched_file: PatchedFile,
) -> list[tuple[int, int]]:
    """
    Extract the ranges of lines that were added or modified in the new file.

    A hunk in unidiff has multiple lines, each either added (+), removed (-),
    or context (space). We collect the target_line_no of every added or
    modified line, then coalesce contiguous line numbers into ranges.

    Returns line ranges in the new file (not the old file). Removed lines
    don't get their own range since they no longer exist in the new content.
    """
    changed_lines: list[int] = []

    for hunk in patched_file:
        for line in hunk:
            # We only care about lines that exist in the NEW file
            if line.is_added and line.target_line_no is not None:
                changed_lines.append(line.target_line_no)

    if not changed_lines:
        return []

    # Coalesce consecutive line numbers into (start, end) ranges
    changed_lines.sort()
    ranges: list[tuple[int, int]] = []
    range_start = changed_lines[0]
    range_end = changed_lines[0]

    for line_no in changed_lines[1:]:
        if line_no == range_end + 1:
            # Extend current range
            range_end = line_no
        else:
            # Close current range, start new one
            ranges.append((range_start, range_end))
            range_start = line_no
            range_end = line_no

    ranges.append((range_start, range_end))
    return ranges


def _reconstruct_new_content(patched_file: PatchedFile) -> str:
    """
    Reconstruct the new file content from the diff.

    NOTE: This only reconstructs the lines that are visible in the diff.
    A real diff typically doesn't include the ENTIRE file — only the changed
    hunks plus context lines. If the analyzer needs the whole file for
    context, the caller should provide it separately (e.g., by reading from
    disk or fetching from the GitHub API).

    For now, we return the visible portion of the new file. This is enough
    for diff-only analysis in step 22, and callers can override by providing
    full content directly.

    Lines are stitched together with newlines, preserving the order they
    appear in the diff hunks. Gaps between hunks are marked with a comment
    so the analyzer knows content is missing.
    """
    if not list(patched_file):
        return ""

    parts: list[str] = []
    last_line_seen = 0

    for hunk in patched_file:
        # If there's a gap between the last hunk and this one, mark it
        hunk_start = hunk.target_start
        if last_line_seen > 0 and hunk_start > last_line_seen + 1:
            gap_size = hunk_start - last_line_seen - 1
            parts.append(f"\n# ... {gap_size} unchanged lines omitted ...\n")

        for line in hunk:
            # Include added and context lines (both exist in the new file)
            if line.is_added or line.is_context:
                content = line.value.rstrip("\n")
                parts.append(content)
                if line.target_line_no is not None:
                    last_line_seen = line.target_line_no

    return "\n".join(parts)
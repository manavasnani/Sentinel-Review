"""
Diff-mode prompt addendum.

Appended to the language-specific system prompt when the analyzer is
running in diff mode (reviewing changed lines in a pull request rather
than a whole file).

The addendum is language-agnostic — it modifies the reviewer's focus,
not what the reviewer knows about vulnerabilities. Instructions here
apply equally to Python, JavaScript, and any future language.
"""

from __future__ import annotations

from typing import Final


# ---------------------------------------------------------------------------
# Diff mode addendum
# ---------------------------------------------------------------------------
#
# Design notes:
#
# 1. The addendum is appended to the END of the base system prompt so it
#    modifies the reviewer's behavior last, closest to the actual review.
#    The model gives more weight to instructions near the end of the prompt.
#
# 2. We explicitly define what "changed" and "context" mean, because the
#    input format (line-numbered code with [CHANGED] markers) is unusual
#    and the model might otherwise ignore or misunderstand the markers.
#
# 3. We handle three cases: entirely new files (review everything), modified
#    files (focus on changes), and files with no diff markers (edge case).
#
# 4. The addendum tells the model to STILL report high-severity pre-existing
#    issues that are directly adjacent to the changes. This catches the case
#    where a developer's new code interacts with existing vulnerable code
#    (e.g., calls a function that has SQL injection). Without this clause,
#    the model might miss real regressions introduced by the PR.

DIFF_MODE_ADDENDUM: Final[str] = """\

# Pull request review mode

You are reviewing a pull request diff, not a complete file. The code below \
has line-level markers indicating which lines are new or modified in this \
PR:

- Lines prefixed with `[CHANGED]` were added or modified in this PR.
- Lines prefixed with `[CONTEXT]` are unchanged surrounding code, provided \
  for reference.
- Lines with no prefix (in files marked as new) represent an entirely \
  new file where every line is a change.

## What to review

Focus your review on the `[CHANGED]` lines and any vulnerabilities they \
introduce. This includes:

1. Vulnerabilities entirely within the changed lines (e.g., a new SQL \
   query built with string concatenation).
2. Vulnerabilities introduced by interaction between changed lines and \
   surrounding context (e.g., a new call to an existing function that \
   has unsafe behavior with attacker input).
3. Removal of security controls (e.g., a change that deletes an \
   authorization check that was previously in place).

## What NOT to report

Do NOT flag pre-existing vulnerabilities that are entirely within \
`[CONTEXT]` lines and unrelated to the PR's changes. The developer \
opened this PR for a specific purpose; flagging unrelated legacy issues \
creates noise and hides real regressions.

Exception: if you find a CRITICAL severity issue in context lines that \
is directly adjacent to changed lines (within 5 lines), report it. \
Critical issues warrant surfacing regardless of scope because they \
represent immediate breach risk.

## Line references

When reporting findings, use the line numbers shown in the numbered code \
below. These are the line numbers in the file AFTER the PR is merged, \
which matches how the developer will navigate to fix issues.

For findings that span both changed and context lines, use the line \
range of the changed portion.
"""
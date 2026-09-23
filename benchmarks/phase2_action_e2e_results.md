# GitHub Action E2E Results

End-to-end validation of Sentinel Review running as a GitHub Action
on a real pull request.

**Date:** 2026-09-22
**Demo repo:** https://github.com/manavasnani/sentinel-review-demo
**PR:** #1 (Add user search and ping endpoints)

## Test Setup

Demo repo with a baseline Flask app on main. PR branch adds two
vulnerable files:

- `search.py` (Python) -- two SQL injection vulnerabilities via string
  concatenation and f-string interpolation
- `api.js` (JavaScript) -- one command injection vulnerability via
  child_process.exec with unsanitized user input

Action configured with `fail_on: high`.

## Results

| File | Language | Findings | CWEs | Severities |
|---|---|---|---|---|
| api.js | JavaScript | 1 | CWE-78 | CRITICAL |
| search.py | Python | 2 | CWE-89, CWE-89 | HIGH, HIGH |
| **Total** | | **3** | | |

## Action Behavior

| Metric | Value |
|---|---|
| Total duration | 1m 0s |
| Analysis time (API calls) | ~55s |
| Files reviewed | 2 |
| Findings | 3 |
| Inline comments posted | 3 |
| Review summary posted | Yes |
| Estimated cost | $0.061 |
| Check status | Failure (fail_on: high triggered) |

## Finding Quality

All three findings were correct:

1. **api.js line 7** -- CWE-78 (CRITICAL): `exec()` with unsanitized
   `req.query.host`. Suggested fix correctly recommends `execFile()` with
   an argument array. Correct CWE, correct severity, correct remediation.

2. **search.py line 20** -- CWE-89 (HIGH): string concatenation in LIKE
   clause with `request.args.get("name")`. Suggested fix correctly shows
   parameterized query with `?` placeholder. Correct CWE, correct severity.

3. **search.py line 31** -- CWE-89 (HIGH): f-string interpolation in
   SELECT with `user_id` from URL route. Suggested fix correctly shows
   parameterized query. Correct CWE, correct severity.

Zero false positives. The baseline `app.py` (health endpoint only) was
not flagged.

## CI Gate Behavior

The Action exited with code 1 because `fail_on: high` was configured
and two HIGH findings were detected. The GitHub check shows as "Failure",
which would block PR merge if branch protection rules require the check
to pass. This is the intended behavior.

## Issues Encountered

1. **Anthropic SDK `temperature` kwarg rejected.** The Docker container
   installed a newer version of the `anthropic` SDK that no longer accepts
   `temperature` as a keyword argument to `messages.create()`. Fixed by
   removing the `temperature` parameter (default is 0 anyway) and pinning
   the SDK version in `pyproject.toml`.

## Verdict

The GitHub Action works end-to-end. It correctly parses the PR event,
fetches the diff, routes files to language-specific prompts, analyzes
changed lines, posts inline comments with accurate findings, and fails
the check when findings exceed the configured threshold. Total cost for
a 2-file PR review: $0.061.
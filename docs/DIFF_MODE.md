# Diff Mode

Sentinel Review can analyze git diffs instead of whole files. This mode
focuses the review on changed lines, which is what you want when reviewing
pull requests.

## Why diff mode exists

When reviewing a whole file, Sentinel flags every vulnerability it finds,
including pre-existing issues unrelated to the current change. In a PR
context, this creates noise. A developer opened the PR to add a feature,
not to fix legacy security debt. Flagging unrelated issues hides the real
regressions the PR introduces.

Diff mode solves this by marking each line as `[CHANGED]` or `[CONTEXT]`
and instructing the model to focus its review on the changed lines.

## How it works

1. The diff parser (`sentinel.diff.parser`) reads a unified diff and
   extracts one `DiffFile` per changed file
2. Each `DiffFile` contains the file's new content, a list of changed
   line ranges, the detected language, and whether the file is new
3. The analyzer formats the code with `[CHANGED]`/`[CONTEXT]` markers
   on each line
4. A diff-mode addendum is appended to the system prompt, instructing
   the model to focus on changed lines
5. Findings are returned with line numbers referring to the new file
   (post-merge)

## Usage

### CLI

Pipe a diff to the `--diff` flag:

```bash
# From git
git diff HEAD~1 | sentinel review --diff

# From a file
cat changes.diff | sentinel review --diff

# With JSON output
git diff main..feature | sentinel review --diff --output json

# With SARIF output
git diff HEAD~1 | sentinel review --diff --sarif results.sarif
```

### GitHub Action

The Action uses diff mode automatically. It fetches the PR diff from
the GitHub API and reviews only the changed files.

## What gets reviewed

The diff parser filters files at parse time:

- **Included:** files with supported extensions (.py, .js, .jsx, .ts, .tsx, etc.)
- **Skipped:** deleted files (nothing to review), binary files, unsupported
  extensions (.md, .json, .yaml, etc.)

## Focus behavior

The diff-mode addendum tells the model:

- Focus on `[CHANGED]` lines and any vulnerabilities they introduce
- Include vulnerabilities caused by interaction between changed lines
  and surrounding context (e.g., a new call to an existing unsafe function)
- Flag removal of security controls (e.g., deleting an auth check)
- Do NOT flag pre-existing vulnerabilities entirely within `[CONTEXT]`
  lines

**Exception:** CRITICAL severity issues in context lines within 5 lines
of a change are still reported. This catches cases where a developer's
new code interacts with adjacent vulnerable code that represents
immediate breach risk.

## New files

When a file is entirely new (`is_new_file=True`), there's no distinction
between changed and unchanged lines. The model reviews the entire file
normally, without `[CHANGED]`/`[CONTEXT]` markers.

## Performance

Diff mode was benchmarked against the same Python corpus as whole-file
mode, with all lines marked as changed (simulating a PR that adds
each file from scratch):

| Metric | Whole-file | Diff mode | Delta |
|---|---|---|---|
| Total findings | 28 | 28 | 0 |
| CWE match rate | 96% | 96% | 0 |
| Severity accuracy | 92% | 92% | 0 |
| Input tokens | 47,618 | 54,519 | +14.5% |
| Cost | $0.358 | $0.387 | +8% |

Zero detection regression. The 14.5% input token increase comes from the
`[CHANGED]`/`[CONTEXT]` markers and the diff-mode addendum. Cost overhead
is about $0.003 per file.

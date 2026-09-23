# Using the GitHub Action

How to set up Sentinel Review as a GitHub Action that automatically reviews
pull requests for security vulnerabilities.

## Quick setup

### 1. Add your Anthropic API key as a repository secret

Go to your repository on GitHub:

1. Click **Settings** > **Secrets and variables** > **Actions**
2. Click **New repository secret**
3. Name: `ANTHROPIC_API_KEY`
4. Value: your Anthropic API key (starts with `sk-ant-`)
5. Click **Add secret**

### 2. Create the workflow file

Create `.github/workflows/sentinel-review.yml` in your repository:

```yaml
name: Sentinel Security Review

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - name: Sentinel Review
        uses: manavasnani/Sentinel-Review@main
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

That's it. Every PR will now get an automated security review.

## Configuration

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `anthropic_api_key` | Yes | -- | Anthropic API key for Claude access |
| `github_token` | No | `${{ github.token }}` | GitHub token for posting reviews |
| `model` | No | `claude-sonnet-4-6` | Claude model to use |
| `fail_on` | No | (empty) | Fail if any finding meets this severity |
| `log_level` | No | `INFO` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) |
| `dry_run` | No | `false` | Log findings without posting a review |
| `sarif_file` | No | (empty) | Path to write SARIF output |

### Failing the check on findings

To block PRs that introduce security issues, set `fail_on` to a severity level:

```yaml
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          fail_on: high
```

This makes the Action exit with code 1 when any finding is HIGH or CRITICAL.
Combined with branch protection rules requiring the check to pass, this
prevents merging PRs with serious security issues.

Severity levels (from most to least severe): `critical`, `high`, `medium`,
`low`, `info`.

### SARIF output for GitHub Security tab

To see Sentinel's findings in your repository's Security tab alongside
CodeQL and other scanners, add a SARIF upload step:

```yaml
jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - name: Sentinel Review
        uses: manavasnani/Sentinel-Review@main
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          sarif_file: sentinel-results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sentinel-results.sarif
```

The `if: always()` ensures SARIF is uploaded even when `fail_on` causes
the Sentinel step to exit with a non-zero code.

### Dry run mode

To test the Action without posting comments on the PR:

```yaml
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          dry_run: "true"
```

Findings are logged in the Action output but not posted as a review.
Useful for initial setup and tuning.

### Using a different model

```yaml
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          model: claude-sonnet-4-6
```

## How it works

When a PR is opened or updated:

1. The Action reads the GitHub event payload to get the PR number and
   commit SHAs
2. It fetches the unified diff for the PR via the GitHub API
3. The diff parser extracts the changed files, filtering out deleted files,
   binary files, and unsupported languages
4. Each file is analyzed with a language-specific security prompt
   (Python or JavaScript/TypeScript)
5. The analysis focuses on the changed lines, not the entire file
6. Findings are formatted as inline PR review comments with severity,
   CWE, description, and a suggested fix
7. The review is posted on the PR in a single API call

## What gets reviewed

The Action reviews files with these extensions:

- Python: `.py`
- JavaScript: `.js`, `.jsx`, `.mjs`, `.cjs`
- TypeScript: `.ts`, `.tsx`

Files with other extensions (`.md`, `.json`, `.yaml`, `.html`, etc.) are
skipped automatically.

Deleted files and binary files are also skipped.

## Cost

Each file review costs approximately $0.03-0.06 depending on file size
and the number of findings. A typical PR touching 2-5 files costs
$0.06-0.30.

Costs are based on Claude Sonnet 4.6 pricing ($3/M input tokens,
$15/M output tokens).

## Permissions

The workflow needs two permissions:

- `contents: read` -- to check out the code and read the diff
- `pull-requests: write` -- to post review comments

The default `GITHUB_TOKEN` provided by Actions has these permissions
when you declare them in the `permissions` block. No personal access
token (PAT) is needed for same-repo PRs.

## Troubleshooting

### "Resource not accessible by integration"

The GitHub token doesn't have write access to PRs. Make sure your
workflow has:

```yaml
permissions:
  contents: read
  pull-requests: write
```

### "ANTHROPIC_API_KEY is not set"

The secret wasn't passed through. Check that:

1. The secret exists in Settings > Secrets > Actions
2. The workflow passes it: `anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}`

### "Event payload does not contain a pull_request field"

The workflow is triggering on a non-PR event. Make sure your trigger is:

```yaml
on:
  pull_request:
    types: [opened, synchronize]
```

### "Validation Failed: pull_request_review_thread.line must be part of the diff"

A finding references a line number that isn't visible in the PR diff.
This can happen when the model reports a line in the surrounding context
rather than in the changed lines. The finding is still valid but can't
be posted as an inline comment on that specific line.

### No review posted but Action succeeds

If the PR only changes files in unsupported languages (e.g., only `.md`
or `.json` files), the Action skips analysis and exits successfully with
no review. This is expected behavior.

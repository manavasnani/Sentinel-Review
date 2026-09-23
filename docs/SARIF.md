# SARIF Output

Sentinel Review can produce output in SARIF 2.1.0 format (Static Analysis
Results Interchange Format). This is the standard format GitHub uses for
its Security tab's code scanning alerts.

## What SARIF gives you

When you upload a SARIF file to GitHub, findings appear in your
repository's **Security > Code scanning alerts** tab. This means
Sentinel's findings show up alongside results from CodeQL, Semgrep,
and any other SARIF-producing tool in a unified dashboard.

Each finding includes:

- The CWE ID and a link to the MITRE CWE entry
- A security-severity score (0.0-10.0) for sorting
- The exact file and line range
- The finding description
- A suggested fix

## Usage

### CLI

```bash
# Generate SARIF alongside normal output
sentinel review --dir src/ --sarif results.sarif

# Single file
sentinel review --file app.py --sarif results.sarif

# Diff mode
git diff HEAD~1 | sentinel review --diff --sarif results.sarif
```

The `--sarif` flag writes the SARIF file in addition to the normal
output (pretty or JSON). You can use both `--output json` and `--sarif`
at the same time.

### GitHub Action

Add a SARIF upload step after the Sentinel Review step:

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

The `if: always()` is important. Without it, the SARIF upload step
is skipped when `fail_on` causes Sentinel to exit with a non-zero code.

## SARIF structure

Sentinel produces a standard SARIF 2.1.0 document:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/...",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Sentinel Review",
          "version": "0.2.0",
          "rules": [...]
        }
      },
      "results": [...]
    }
  ]
}
```

### Rules

Each unique CWE ID becomes a SARIF rule. Rules include:

- `id`: the CWE ID (e.g., "CWE-89")
- `shortDescription`: CWE ID and finding title
- `helpUri`: link to the MITRE CWE entry
- `properties.security-severity`: numeric score for GitHub's severity sorting

### Results

Each finding becomes a SARIF result with:

- `ruleId`: the CWE ID
- `level`: "error" (critical/high), "warning" (medium), or "note" (low/info)
- `message.text`: the finding description
- `locations`: file path and line range
- `fixes`: the suggested remediation
- `fingerprints`: a stable identifier for deduplication across runs

## Severity mapping

| Sentinel severity | SARIF level | Security score |
|---|---|---|
| critical | error | 9.5 |
| high | error | 8.0 |
| medium | warning | 5.5 |
| low | note | 3.0 |
| info | note | 1.0 |

## Deduplication

Each finding gets a fingerprint based on `file_path:cwe_id:line_start`.
GitHub uses this to track whether an alert is new, fixed, or still open
across multiple runs. If you fix a vulnerability and re-run the Action,
the corresponding alert is automatically closed.

## Requirements

To use SARIF with GitHub's code scanning:

- The repository must have GitHub Advanced Security enabled (free for
  public repos, paid feature for private repos on GitHub Enterprise)
- The workflow must have `security-events: write` permission to upload
  SARIF files

Add this to your workflow permissions:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
```

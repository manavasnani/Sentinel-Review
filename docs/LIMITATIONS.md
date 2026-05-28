# Limitations

An honest list of what Sentinel Review can't do, where it struggles, and what you should know before relying on it.

## Single-file context only

The biggest limitation right now. The analyzer sends one file at a time to Claude. It has no visibility into other files in the project. This means it can't:

- Follow a function call from `routes.py` into `utils.py` to see if input gets sanitized there
- Check if a middleware applies authentication before the vulnerable endpoint is reached
- Verify whether a database query in `models.py` is only called from a safe context in `views.py`
- Detect vulnerabilities that span multiple files (e.g., a config file that disables CSRF globally)

In practice, this causes two problems. First, it can miss vulnerabilities where the dangerous sink is in a different file from the untrusted source. Second, it can false-flag code that looks dangerous in isolation but is actually protected by something in another file (though this hasn't happened in testing so far, probably because the `confidence: low` calibration catches these cases).

Phase 3 plans to add multi-file context by pulling imports, called functions, and config files into the prompt alongside the target file. This is the highest-priority improvement.

## Python only (for now)

The system prompt, few-shot examples, and anti-pattern rules are all Python-specific. The prompt mentions `psycopg2`, `subprocess`, `bcrypt`, `Jinja2`, `Flask`, and other Python ecosystem libraries.

Claude itself understands most programming languages, so if you point the tool at a JavaScript file it will probably catch some things. But the false positive rate will be higher (no JS-specific anti-patterns) and the CWE taxonomy won't be as precise (no JS-specific few-shot examples).

Adding a new language is mostly a prompt engineering task, not a code change. The analyzer, models, CLI, and formatters are all language-agnostic. You'd need a language-specific prompt with the right safe-pattern rules and few-shot examples, plus a test corpus to benchmark against.

## Cost at scale

At ~$0.036 per file and ~21 seconds per file, scanning a large codebase gets expensive and slow:

| Project size | Estimated cost | Estimated time |
|---|---|---|
| 10 files | $0.36 | ~3.5 min |
| 50 files | $1.80 | ~17 min |
| 100 files | $3.60 | ~35 min |
| 500 files | $18.00 | ~2.9 hours |
| 1000 files | $36.00 | ~5.8 hours |

For comparison, Bandit scans 1000 files in under 10 seconds for free.

The right approach for large projects isn't to scan everything with the LLM. It's the Phase 3 hybrid pipeline: run Semgrep or Bandit first (free, fast), then use the LLM only on files that Semgrep flags or on diffs in pull requests. This brings the per-PR cost down to a few cents since most PRs touch 5-15 files.

Phase 2's diff-based scanning also helps. Instead of scanning entire files, you only send changed lines plus surrounding context. This cuts token usage significantly.

## Non-determinism

Even with `temperature=0`, Claude's output isn't perfectly deterministic. Two runs on the same file will usually produce the same findings, but occasionally a finding will appear in one run and not the other, or the severity/confidence will differ slightly.

For Phase 1 (interactive CLI use), this is fine. For Phase 2 (CI/CD gating), it's a problem because you don't want a PR to pass on one run and fail on a retry. The planned mitigation is a "run twice, only flag findings that appear in both" mode, at the cost of doubling the API spend.

## No binary or compiled code

The tool only works on source code that can be read as UTF-8 text. It can't analyze compiled binaries, bytecode, minified JavaScript, or obfuscated code. This is inherent to the approach since we're sending code as text to an LLM.

## No runtime analysis

This is static analysis only. It can't detect vulnerabilities that depend on runtime state, configuration, or environment. Examples:

- A SQL query that's safe when a certain middleware is enabled but vulnerable when it's not
- An endpoint that's only reachable through a specific load balancer configuration
- Race conditions that depend on timing and concurrency patterns
- Vulnerabilities in dynamically generated code (e.g., `exec()` on code built at runtime from a database)

## Token limits on large files

Claude has a context window limit. Very large files (2000+ lines) may exceed the token budget, especially when combined with the system prompt and few-shot examples. The current implementation doesn't handle this. It just sends the file and hopes it fits.

A better approach would be to split large files into logical chunks (by function or class) and analyze each chunk separately. This is a Phase 3 improvement.

## No incremental analysis

Every run re-analyzes the file from scratch. There's no caching or diffing against previous results. If you run the tool on the same unchanged file twice, you pay twice.

Phase 3 plans to add a caching layer keyed on file content hash + prompt version, so unchanged files skip the API call entirely.

## Vulnerability classes not covered

The prompt is scoped to the OWASP Top 10 and common CWE Top 25 entries. Some vulnerability types are not in scope:

- Business logic flaws beyond IDOR (e.g., negative quantities in a shopping cart)
- Denial of service via algorithmic complexity (ReDoS, hash collision attacks)
- Memory safety issues (buffer overflows, use-after-free) since these don't apply to Python
- Supply chain vulnerabilities (malicious dependencies)
- Infrastructure misconfigurations (Dockerfile issues, Terraform, Kubernetes YAML)
- Mobile-specific vulnerabilities (insecure storage, certificate pinning)

Some of these could be added by extending the prompt. Others (like supply chain analysis) require a fundamentally different approach.

## It's not a replacement for manual review

This tool catches patterns. A skilled AppSec engineer doing a manual review brings context that no tool has: understanding of the business domain, knowledge of the deployment environment, awareness of compensating controls, and judgment about actual risk vs theoretical risk.

Sentinel is best used as a first pass that catches the obvious stuff so human reviewers can focus on the hard stuff. The README and all documentation frame it as "complementary to traditional SAST," not a replacement for human review. Don't change that framing.

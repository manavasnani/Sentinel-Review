# Limitations

What Sentinel Review can't do, where it's less reliable, and what to
be aware of when using it.

## Single-file analysis

Sentinel reviews one file at a time. It cannot trace data flow across
files. If a request parameter is validated in `middleware.py` and used
unsafely in `handler.py`, Sentinel sees only `handler.py` and may flag
it as unsafe even though the validation exists elsewhere.

This is the biggest structural limitation. Cross-file data flow analysis
requires a fundamentally different architecture (AST-based, not
LLM-based). Tools like CodeQL and Semgrep handle this; Sentinel is
complementary, not a replacement.

## Non-deterministic output

LLM output is inherently non-deterministic. Running the same file twice
may produce slightly different findings: different descriptions, slightly
different line ranges, occasionally a missed or extra finding.

Sentinel mitigates this by setting temperature to 0 and using structured
output (tool use), but true determinism is not achievable with current
LLM technology.

In practice, the core findings (which CWEs are flagged, at what severity)
are stable across runs. The variation is mostly in the prose (descriptions,
reasoning) and occasionally in line-range precision.

## Cost

Each file review costs approximately $0.03-0.06 depending on file size
and finding count. This adds up:

| Scale | Approximate cost |
|---|---|
| 1 file | $0.03-0.06 |
| 10 files | $0.30-0.60 |
| 50 files | $1.50-3.00 |
| 100 files | $3.00-6.00 |

For large repositories, reviewing every file on every PR is expensive.
Diff mode helps by reviewing only changed files, but cost is still
proportional to the number of changed files and their size.

## Language coverage

Only Python and JavaScript/TypeScript are supported. Java, Go, Ruby,
C/C++, and other languages are not covered. Files in unsupported
languages are silently skipped.

## CWE taxonomy precision

The model sometimes uses parent or sibling CWE IDs instead of the most
specific child:

| Vulnerability | Ideal CWE | Model's CWE | Notes |
|---|---|---|---|
| NoSQL injection (MongoDB) | CWE-943 | CWE-89 | Model treats all injection as SQL injection |
| ReDoS (regex backtracking) | CWE-1333 | CWE-400 | Uses generic resource consumption parent |
| JWT verification skipping | CWE-347 | CWE-287 | Tags by impact (auth bypass) not root cause |

Detection is correct in all three cases. The description and suggested
fix are accurate. Only the CWE ID metadata is imprecise. This is a
known limitation of using an LLM for CWE classification: the model's
training data favors common CWE IDs over rare ones.

## False negatives

Sentinel does not catch everything. Known blind spots:

- **Business logic flaws** that require understanding the application's
  intended behavior (e.g., "users shouldn't be able to set their own
  discount percentage")
- **Race conditions** that depend on timing and concurrency patterns
  not visible in a single code review
- **Supply chain vulnerabilities** in dependencies (use `npm audit` or
  `pip-audit` for this)
- **Configuration issues** in deployment files (Kubernetes manifests,
  Terraform, nginx.conf)
- **Subtle type confusion** in TypeScript where runtime types differ
  from compile-time types

## False positives

False positive rate is 0% across the test corpus (8 clean samples across
two languages). However, the test corpus is small and deliberately
constructed. In real-world code, false positives may occur:

- Code that uses a dangerous API but has validation happening in a
  different file or earlier in the same function outside the visible
  context
- Internal-only endpoints that the model rates as externally accessible
- Test code that intentionally uses unsafe patterns

## Diff-mode limitations

In diff mode, Sentinel focuses on changed lines and may miss:

- Pre-existing vulnerabilities in unchanged code that interact with the
  new changes (mitigated by the 5-line adjacency exception for critical
  findings)
- Vulnerabilities introduced by removing security controls (the model
  is instructed to flag these, but detection quality depends on the
  clarity of the removal in the diff)

## Rate limits

The Anthropic API has rate limits. If you're reviewing many files in
rapid succession (e.g., a large directory scan), you may hit rate limits.
Sentinel has built-in retry logic with exponential backoff, but extreme
volumes (100+ files in one run) may still fail.

## Context window

Very large files (1000+ lines) may approach the model's context window
limit. Sentinel does not currently split large files or truncate them.
If a file exceeds the context window, the API call will fail with an
error.

## Token cost reporting

The estimated cost shown in output and PR comments is calculated from
token counts using published Anthropic pricing. Actual billed cost may
differ slightly due to rounding, prompt caching, or pricing changes.

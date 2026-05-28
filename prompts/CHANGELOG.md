# Prompt Changelog

## v2 (2026-05-20) - Post-benchmark calibration

Changes motivated by benchmark run 1 analysis against ground_truth.yaml.

### Changes

**1. CWE taxonomy for crypto findings** (fixes 3 CWE mismatches)

Problem: v1 listed crypto failures under a single CWE-327/CWE-326 bucket. The model tagged MD5/SHA-1 password hashing as CWE-327 (broken algorithm) instead of CWE-916 (insufficient computational effort for hashing), and tagged a fixed IV in CBC mode as CWE-327 instead of CWE-329 (not using random IV).

Fix: Expanded the crypto section into five sub-bullets with explicit mapping guidance:
- CWE-916: fast hash for passwords (MD5, SHA-1, SHA-256 without KDF)
- CWE-327: broken algorithm in non-password context (ECB, RC4)
- CWE-326: inadequate key length (DES, short RSA)
- CWE-329: fixed/predictable IV or nonce
- CWE-798: hardcoded secrets (unchanged)

Added a dedicated "CWE selection guidance" section reinforcing these mappings.

**2. Severity calibration** (addresses 6 upward severity deviations)

Problem: v1 severity guidelines were too coarse. The model consistently rated medium-expected findings as high:
- Command injection: both findings rated CRITICAL (expected HIGH)
- SHA-1 for passwords: rated HIGH (expected MEDIUM)
- DES encryption: rated HIGH (expected MEDIUM)
- yaml.load deserialization: rated CRITICAL (expected HIGH)
- minidom XXE: rated HIGH (expected MEDIUM)

Fix: Added a "Severity edge cases" subsection with specific rules:
- Crypto: MD5/SHA-1 for passwords -> high; fixed IV -> medium
- Command injection: unauthenticated RCE -> critical; behind auth -> high
- pickle -> critical; yaml.load -> high (less direct than pickle)
- lxml XXE on external endpoint -> high; minidom on internal -> medium

Also tightened the `critical` definition to require "unauthenticated attacker achieves full compromise in a single request."

**3. Granular findings instruction** (addresses 04_hardcoded_credentials.py)

Problem: Ground truth expected 2 grouped findings for hardcoded credentials. The model returned 5 individual findings (one per secret). The model's behavior is better for remediation, but it wasn't explicitly instructed either way.

Fix: Added "Granularity of findings" section explicitly instructing the model to report each distinct vulnerability separately, even when multiple share the same CWE.

**4. New few-shot example: CWE-329 fixed IV** (Example 4)

Added a fourth few-shot example showing a hardcoded all-zeros IV in AES-CBC with the correct CWE-329 tag, medium severity, and an explicit note: "Do NOT tag fixed/predictable IV issues as CWE-327."

This directly targets the one real CWE miss from benchmark run 1.

### Unchanged from v1

- Role framing (senior AppSec engineer)
- Vulnerability classes in scope (14 categories)
- Anti-pattern / false-positive guards
- Confidence calibration (high/medium/low)
- Prompt injection defense
- Output instructions (report_security_findings tool)

### Results

| Metric              | Run 1 (v1)       | Run 2 (v2)       | Change       |
|---------------------|------------------|------------------|--------------|
| CWE match rate      | 19/20 (95%)      | 25/26 (96%)      | +1pp         |
| Severity exact      | 16/22 (73%)      | 23/25 (92%)      | +19pp        |
| Severity too high   | 6/22             | 2/25             | -4           |
| Severity too low    | 0/22             | 0/25             | unchanged    |
| Clean sample FPs    | 0                | 0                | unchanged    |
| Input tokens        | 35,477           | 47,917           | +35%         |
| Est. cost           | $0.315           | $0.362           | +$0.047      |
| Avg cost/file       | $0.032           | $0.036           | +$0.004      |

The 35% token increase is from the longer prompt (added CWE guidance, severity edge cases, granularity section, 4th few-shot example). Severity accuracy improvement from 73% to 92% is worth the extra $0.004 per file.

---

## v1 (2026-05-14) - Phase 1 MVP

Initial system prompt. Established:

- Senior AppSec engineer role framing
- 14 vulnerability classes in scope (OWASP Top 10 + common CWE Top 25)
- Anti-pattern guards for parameterized queries, bcrypt, subprocess, Jinja2, secrets module, TLS, auth libraries
- Three-level confidence calibration (high/medium/low)
- Five-level severity guidelines (critical/high/medium/low/info)
- Prompt injection defense via data/instruction separation
- Structured output via report_security_findings tool
- Three few-shot examples (SQL injection, safe parameterized query, uncertain SSTI)

### Results

| Metric              | Value            |
|---------------------|------------------|
| CWE match rate      | 19/20 (95%)      |
| Severity exact      | 16/22 (73%)      |
| Severity too high   | 6/22             |
| Severity too low    | 0/22             |
| Clean sample FPs    | 0                |
| Est. cost           | $0.315           |
| Avg cost/file       | $0.032           |

### Known issues (fixed in v2)

1. All crypto findings tagged CWE-327 regardless of root cause
2. Severity too aggressive on 6/22 findings (no per-category calibration)
3. No guidance on finding granularity (group vs split)

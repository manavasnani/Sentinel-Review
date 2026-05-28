# Bandit vs Sentinel Review — Benchmark Comparison

Comparison of [Bandit](https://bandit.readthedocs.io/) (rule-based SAST) against Sentinel Review (LLM-powered, Claude Sonnet 4.6) on the same 10-file vulnerable test corpus.

**Bandit version:** run via `bandit -r examples/vulnerable_samples/ -f json`
**Sentinel version:** prompt v2, benchmark run 2
**Date:** 2026-05-20

---

## Headline

| Metric | Bandit | Sentinel | 
|---|---|---|
| CWE categories matched (of 14) | **4 (29%)** | **13 (93%)** |
| Files with zero correct detections | 5 / 10 | 0 / 10 |
| Total findings returned | 24 | 28 |
| False positives on clean samples | 0 | 0 |
| Cost per run | Free | ~$0.36 |
| Time per run | <1s | ~210s |

Sentinel detected 3.25x more vulnerability categories than Bandit on the same corpus. Bandit returned a comparable number of raw findings (24 vs 28), but most of its findings were either low-severity informational warnings or used imprecise CWE tags that didn't match the actual root cause.

---

## Per-File Breakdown

### 01_sql_injection.py
**Ground truth:** 2× CWE-89 (SQL injection)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ✅ Partial | Found both SQLi instances but flagged them as MEDIUM/LOW confidence. Also flagged `debug=True` (CWE-94) which is real but not in scope. |
| Sentinel | ✅ Full | Both findings tagged HIGH severity, HIGH confidence, with correct CWE-89 and actionable fix suggestions. |

**Verdict:** Both tools detect SQLi. Sentinel provides better severity calibration and remediation guidance.

### 02_command_injection.py
**Ground truth:** 2× CWE-78 (command injection)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ✅ Full | Found both `os.system` and `subprocess shell=True`. Also returned 3 additional LOW-severity informational findings about subprocess usage. |
| Sentinel | ✅ Full | Both findings tagged CRITICAL with concrete exploit reasoning. |

**Verdict:** Both tools detect command injection. Bandit adds noise with informational subprocess warnings. Sentinel provides cleaner, more actionable output.

### 03_path_traversal.py
**Ground truth:** 2× CWE-22 (path traversal)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ❌ Missed | Zero findings. Bandit has no rule for path traversal via `os.path.join` with unsanitized input. |
| Sentinel | ✅ Full | Both traversal vectors detected with correct CWE-22, HIGH severity. |

**Verdict:** Sentinel wins. Path traversal requires understanding that user input flows into a filesystem API — exactly the kind of source-to-sink reasoning that pattern matching can't do.

### 04_hardcoded_credentials.py
**Ground truth:** 5× CWE-798 (hardcoded secrets)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ⚠️ Wrong CWE | Found 3 secrets but tagged them CWE-259 (hardcoded password), not CWE-798 (hardcoded credentials). Also flagged 3 unrelated `requests` timeout warnings (CWE-400). Missed the JWT key and AWS access key ID. |
| Sentinel | ✅ Full | All 6 credentials found (5 module-level + 1 URL-embedded), each as a separate CWE-798 finding. |

**Verdict:** Sentinel wins on both coverage and precision. Bandit's CWE-259 is a related but less precise tag, and it missed 2 of the 5 secrets entirely.

### 05_weak_crypto.py
**Ground truth:** CWE-916 (MD5/SHA-1 for passwords), CWE-327 (AES-ECB), CWE-326 (DES), CWE-329 (fixed IV)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ⚠️ Partial | Found MD5, SHA-1, and DES, but tagged everything as CWE-327. Cannot distinguish between password-hashing misuse (CWE-916), weak key length (CWE-326), and fixed IV (CWE-329). Missed the fixed IV entirely. Also flagged pyCrypto deprecation (informational). |
| Sentinel | ✅ Full | All 5 expected findings with correct differentiated CWEs (916, 327, 326, 329). Also found a bonus CWE-329 on the DES function's hardcoded IV. |

**Verdict:** Sentinel wins decisively. CWE taxonomy precision matters for remediation — telling a developer "use bcrypt" (CWE-916) is different from "use a random IV" (CWE-329), even though both fall under "cryptographic failures." Bandit treats them all the same.

### 06_ssrf.py
**Ground truth:** 2× CWE-918 (SSRF)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ❌ Missed | Zero findings. Bandit has no SSRF detection — it cannot reason about whether a URL is user-controlled. |
| Sentinel | ✅ Full | Both SSRF vectors detected with correct CWE-918, HIGH severity. |

**Verdict:** Sentinel wins. SSRF detection requires understanding data flow from `request.json` to `requests.get()`. Pattern matching can't infer this.

### 07_insecure_deserialization.py
**Ground truth:** CWE-502 (pickle.loads = critical, yaml.load = high)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ✅ Full | Found both pickle and yaml.load. Tagged pickle as MEDIUM (Sentinel: CRITICAL) and yaml as MEDIUM/CWE-20 (Sentinel: HIGH/CWE-502). |
| Sentinel | ✅ Full | pickle tagged CRITICAL, yaml.load tagged HIGH. Both CWE-502 with detailed reasoning about exploitability differences. |

**Verdict:** Both detect the issues. Sentinel provides better severity differentiation (pickle is RCE → critical; yaml.load is less direct → high) and uses the correct CWE-502 for both instead of CWE-20.

### 08_idor.py
**Ground truth:** CWE-639 (IDOR on read), CWE-285 (missing auth on delete)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ❌ Missed | Zero findings. IDOR and authorization flaws are logic vulnerabilities invisible to pattern-matching tools. |
| Sentinel | ✅ Full | Both endpoints flagged as CWE-639 (IDOR) with reasoning about the missing ownership check. |

**Verdict:** Sentinel wins. This is the canonical example of why LLM-based review exists — authorization logic flaws require understanding *intent* ("this endpoint should only return the requesting user's invoices") which no regex or AST pattern can express.

### 09_xxe.py
**Ground truth:** 2× CWE-611 (XXE)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ⚠️ Wrong CWE | Found both XML parsing issues but tagged them CWE-20 (improper input validation) instead of CWE-611 (XXE). Missed the lxml finding entirely — only caught minidom. |
| Sentinel | ✅ Full | Both findings with correct CWE-611. lxml tagged HIGH, minidom tagged MEDIUM (appropriate severity differentiation). |

**Verdict:** Sentinel wins. CWE-20 is a parent category that's too vague — CWE-611 tells the developer exactly what the problem is and what to fix (disable external entity processing).

### 10_open_redirect.py
**Ground truth:** 2× CWE-601 (open redirect)

| Tool | Detected? | Notes |
|---|---|---|
| Bandit | ❌ Missed | Zero findings. Bandit cannot detect open redirects — it requires understanding that `request.args.get("next")` flows to `redirect()` without validation. |
| Sentinel | ✅ Full | Both redirect vectors detected with CWE-601, MEDIUM severity. |

**Verdict:** Sentinel wins. Open redirect detection requires tracing user input through Flask's `redirect()` function — a data-flow analysis Bandit doesn't perform.

---

## What Bandit Catches That Sentinel Doesn't

Bandit flagged a few things Sentinel did not:

| Finding | CWE | File | Assessment |
|---|---|---|---|
| `debug=True` in Flask | CWE-94 | 01_sql_injection.py | Real issue (Werkzeug debugger exposed), but not in scope for this corpus. |
| `requests` calls without `timeout` | CWE-400 | 04_hardcoded_credentials.py | Valid low-severity finding. Could cause DoS via hung connections. |
| pyCrypto deprecation warning | CWE-327 | 05_weak_crypto.py | Informational — flags the library as unmaintained, not a specific vulnerability. |

These are legitimate but low-impact findings. Sentinel could be prompted to detect missing request timeouts, but it was scoped to OWASP Top 10 vulnerability classes for Phase 1.

---

## Where Bandit Fundamentally Cannot Compete

Five vulnerability classes in the corpus are invisible to Bandit because they require semantic reasoning, not pattern matching:

| Category | Why Bandit Can't Detect It |
|---|---|
| **Path traversal** (CWE-22) | Requires tracing user input through `os.path.join` to a file-read operation. The function call itself is legitimate — the vulnerability is in how the argument is sourced. |
| **SSRF** (CWE-918) | Requires understanding that a URL passed to `requests.get()` originates from user input without an allowlist check. |
| **IDOR** (CWE-639) | Requires understanding business logic: "this database query should filter by the authenticated user's ID, but it doesn't." No syntactic pattern exists for this. |
| **Open redirect** (CWE-601) | Requires tracing `request.args` through to Flask's `redirect()` without validation. The `redirect()` call itself is normal. |
| **CWE taxonomy precision** | Bandit maps findings to broad CWE categories (CWE-327 for all crypto, CWE-20 for all input validation). It cannot distinguish CWE-916 from CWE-329 from CWE-326 because that requires understanding the *context* of the API usage. |

---

## Cost-Benefit Analysis

| Factor | Bandit | Sentinel |
|---|---|---|
| Detection rate | 29% of vulnerability categories | 93% of vulnerability categories |
| Cost | Free (open source) | ~$0.036 per file (~$0.36 for 10 files) |
| Speed | <1 second for entire corpus | ~210 seconds (21s/file average) |
| CI integration | Native, well-established | Phase 2 (GitHub Actions) |
| Determinism | Fully deterministic | Near-deterministic (temperature=0) |
| Explainability | Generic rule descriptions | Context-specific reasoning per finding |
| False positives | Higher noise (informational warnings) | Lower (scoped to exploitable issues) |

Bandit is the right tool for catching the easy stuff fast and free. Sentinel is the right tool for catching the hard stuff that pattern matching misses. They are complementary, not competing — which is why Phase 3 of this project integrates Semgrep as a pre-filter with the LLM as the deep-analysis pass.

---

## Conclusion

On a 10-file corpus covering the OWASP Top 10, Bandit detected **29%** of vulnerability categories while Sentinel detected **93%**. The gap is not a Bandit quality problem — Bandit is excellent at what it does. The gap exists because five of the ten vulnerability classes in this corpus (path traversal, SSRF, IDOR, open redirect, and fine-grained crypto taxonomy) fundamentally require semantic understanding of code intent, data flow, and business logic that rule-based pattern matching cannot provide.

The cost of that additional coverage is ~$0.036 per file and ~21 seconds of latency per file. For a security review where a missed vulnerability could mean a data breach, that tradeoff is straightforward.
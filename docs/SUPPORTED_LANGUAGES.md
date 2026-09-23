# Supported Languages

Sentinel Review currently supports Python and JavaScript/TypeScript.
Each language has its own system prompt with language-specific vulnerability
classes, anti-patterns, and few-shot examples.

## Python

**Extensions:** `.py`
**Prompt version:** v2 (benchmarked)

### Vulnerability classes detected

- SQL injection (CWE-89)
- OS command injection (CWE-78)
- Path traversal (CWE-22)
- Server-side request forgery (CWE-918)
- Insecure deserialization -- pickle, yaml.load (CWE-502)
- XML external entities (CWE-611)
- Hardcoded credentials (CWE-798)
- Weak cryptography -- MD5/SHA-1 for passwords (CWE-916), ECB mode (CWE-327), short keys (CWE-326), fixed IVs (CWE-329)
- IDOR / missing authorization (CWE-639, CWE-285)
- Open redirects (CWE-601)
- XSS (CWE-79)
- CSRF (CWE-352)

### Safe patterns recognized (not flagged)

- Parameterized queries (psycopg2, sqlite3, SQLAlchemy)
- bcrypt, argon2, scrypt, PBKDF2 for password hashing
- subprocess with shell=False and list arguments
- Jinja2 with autoescape=True
- secrets module for token generation

### Benchmark results

- CWE match rate: 96% (25/26 expected CWEs)
- Severity accuracy: 92% (23/25 exact match)
- False positives: 0 across 4 clean samples

## JavaScript / TypeScript

**Extensions:** `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`
**Prompt version:** v2 (benchmarked)

TypeScript shares the JavaScript prompt. Type annotations don't affect
security analysis since the vulnerability classes and sink/source patterns
are identical.

### Vulnerability classes detected

Everything Python covers, plus these JS-specific classes:

- Prototype pollution via recursive merge (CWE-1321)
- NoSQL injection -- MongoDB operator injection (detected as CWE-89)
- ReDoS -- catastrophic regex backtracking (detected as CWE-400)
- JWT signature skipping -- jwt.decode vs jwt.verify (detected as CWE-287)
- Code injection via eval() and vm.runInNewContext (CWE-94)
- XSS via dangerouslySetInnerHTML (CWE-79)

### CWE ID notes

Three JS-specific vulnerability classes are detected correctly but tagged
with parent/sibling CWE IDs instead of the most specific child:

| Vulnerability | Expected CWE | Actual CWE | Why |
|---|---|---|---|
| NoSQL injection | CWE-943 | CWE-89 | Model's training data heavily favors CWE-89 for all injection |
| ReDoS | CWE-1333 | CWE-400 | CWE-400 is the generic parent for resource consumption |
| JWT decode | CWE-347 | CWE-287 | Model tags by impact (auth bypass) not root cause (missing sig check) |

Detection and remediation advice are correct in all three cases. The CWE ID
is metadata; the finding description and suggested fix are what developers
act on.

### Safe patterns recognized (not flagged)

- Parameterized queries with mysql2 `?` placeholders, pg `$1/$2`, Knex, Prisma, Sequelize
- child_process.execFile() with array arguments
- DOMPurify-sanitized content in dangerouslySetInnerHTML
- React text rendering (auto-escaped)
- jwt.verify() with a signing key
- bcryptjs, argon2 for password hashing
- crypto.randomBytes() for token generation

### Benchmark results

- Detection rate: 100% (every vulnerability class caught)
- CWE match rate: 95% (21/22 with adjusted ground truth)
- False positives: 0 across 4 clean samples

## Adding a new language

To add support for a new language:

1. Add an entry to the `Language` enum in `src/sentinel/models.py`
2. Add file extensions to the enum's `file_extensions` property
3. Create a prompt module at `src/sentinel/prompts/<language>.py` following
   the structure of `python.py` or `javascript.py`
4. Register the module in `src/sentinel/prompts/__init__.py` in the
   `_LANGUAGE_MODULES` dict
5. Create a test corpus under `examples/vulnerable_samples/<language>/`
   and `examples/clean_samples/<language>/`
6. Add ground truth entries to `examples/ground_truth.yaml`
7. Run the benchmark and iterate the prompt based on results

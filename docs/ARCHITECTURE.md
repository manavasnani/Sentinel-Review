# Architecture

How Sentinel Review is structured and why it's built the way it is.

## System diagram

```
                              ┌─────────────────────┐
                              │     CLI (cli.py)     │
                              │  Typer command parser │
                              │  --file / --dir      │
                              │  --output / --fail-on│
                              └─────────┬───────────┘
                                        │
                                        ▼
                              ┌─────────────────────┐
                              │   File reader        │
                              │   UTF-8 validation   │
                              │   Directory walker   │
                              └─────────┬───────────┘
                                        │
                                        ▼
                              ┌─────────────────────┐
                              │  Prompt construction │
                              │    (prompts.py)      │
                              │                      │
                              │  ┌────────────────┐  │
                              │  │ System prompt   │  │
                              │  │ (v2, cached)    │  │
                              │  └────────────────┘  │
                              │  ┌────────────────┐  │
                              │  │ Few-shot        │  │
                              │  │ examples (x4)   │  │
                              │  └────────────────┘  │
                              │  ┌────────────────┐  │
                              │  │ Line-numbered   │  │
                              │  │ code in fences  │  │
                              │  └────────────────┘  │
                              └─────────┬───────────┘
                                        │
                                        ▼
                              ┌─────────────────────┐
                              │   Anthropic API      │
                              │   (analyzer.py)      │
                              │                      │
                              │  model: sonnet-4.6   │
                              │  temperature: 0      │
                              │  tool_choice: forced  │
                              │  retry: exp. backoff │
                              └─────────┬───────────┘
                                        │
                                        ▼
                              ┌─────────────────────┐
                              │  Response parsing    │
                              │                      │
                              │  Extract tool_use    │
                              │  block from response │
                              │         │            │
                              │         ▼            │
                              │  Pydantic validation │
                              │  (models.py)         │
                              │  - CWE format check  │
                              │  - line range check  │
                              │  - enum validation   │
                              │  - skip malformed    │
                              └─────────┬───────────┘
                                        │
                                        ▼
                              ┌─────────────────────┐
                              │  Output              │
                              │  (formatters.py)     │
                              │                      │
                              │  pretty: Rich panels │
                              │  json: Pydantic dump │
                              └─────────────────────┘
```

## Module responsibilities

| Module | Responsibility | Depends on |
|---|---|---|
| `exceptions.py` | Custom exception hierarchy | nothing |
| `models.py` | Pydantic schemas (Finding, ReviewResult, enums) | nothing |
| `config.py` | Env var loading, SentinelConfig dataclass | exceptions |
| `prompts.py` | System prompt, few-shot examples, request formatting | nothing |
| `analyzer.py` | Claude API calls, retry logic, response parsing | everything above |
| `formatters.py` | JSON and Rich terminal rendering | models |
| `cli.py` | Typer commands, arg parsing, exit codes | everything |
| `__init__.py` | Public API re-exports | everything |

The dependency flow is strictly one-directional. No circular imports. Each module can be tested in isolation by mocking its dependencies.

## Key design decisions

### Structured output via tool use

This is the most important design decision in the project. Instead of asking Claude to "output JSON" and parsing the response, we define a JSON Schema as a tool and force Claude to call it using `tool_choice: {"type": "tool", "name": "report_security_findings"}`.

Why this matters:
- The API enforces the schema. If a required field is missing or a severity value isn't in the enum, the API rejects it before we ever see the response. No more "the model forgot to close a JSON bracket" failures.
- `tool_choice: forced` guarantees Claude calls the tool. Without it, the model might decide "no vulnerabilities found, let me just say so in prose" and the parser breaks.
- The schema mirrors the Pydantic `Finding` model, so validation happens twice: once by the API, once by Pydantic. Belt and suspenders.

The alternative (asking for raw JSON) works 90% of the time and breaks in annoying ways the other 10%: markdown fences around the JSON, trailing commas, missing fields, extra fields the model invented. Tool use eliminates all of these.

### Frozen, immutable data models

Both `Finding` and `ReviewResult` are frozen (`frozen=True` in Pydantic, `frozen=True` in the config dataclass). Once a finding is created, nothing can mutate it.

Why:
- No downstream code can silently "fix" a severity rating to suppress an inconvenient finding
- Frozen objects are hashable, which means you can put them in sets for deduplication (needed in Phase 3)
- Makes it obvious at the code level that findings are facts, not drafts

### Two consoles (stdout vs stderr)

The CLI has two Rich consoles: `stdout_console` for actual output and `stderr_console` for status messages and errors.

This seems like overengineering until you try to pipe JSON output:

```bash
sentinel review --file app.py --output json > findings.json
```

If status messages ("Reviewing 3 files...") go to stdout, they end up in `findings.json` and the JSON is broken. Splitting the streams means `> findings.json` captures only valid JSON while progress messages still appear in the terminal.

### Exit codes as an API

The CLI exit codes are designed for CI consumption:
- 0: clean, no findings above threshold
- 1: findings exceeded the threshold (fail the build)
- 2: bad user input (missing args, invalid format)
- 3: API or parse failure (transient, retry)

This lets CI scripts distinguish "the tool found problems" (1) from "the tool itself broke" (3). Most CLIs collapse everything into 0/1, which makes it impossible to tell whether a CI failure means "insecure code" or "the API was down."

### Defensive response parsing

When the model returns findings, the parser validates each one individually through Pydantic. If one finding has a malformed CWE or an invalid line range, it logs a warning and skips that finding instead of crashing the entire review.

This matters because LLMs occasionally produce slightly wrong data (CWE without the dash, `line_end` before `line_start`). Crashing on the first malformed finding would mean losing 9 valid findings because of 1 bad one.

### API key never in repr()

The `SentinelConfig` dataclass marks the `api_key` field with `repr=False`. This means if the config object ever appears in a log, a stack trace, or a `print()` call during debugging, the key is excluded.

For a security tool, leaking your own API key in logs would be embarrassing. This is defense in depth at the language level.

### Retry with exponential backoff

The analyzer retries on rate limits (429) and timeouts with exponential backoff (1s, 2s, 4s, 8s). It does NOT retry on 4xx errors (except 429) because those indicate a problem with the request itself, and retrying won't help.

This is standard practice for API clients, but it matters more here because a single corpus run makes 10+ sequential API calls. Without retry logic, a single rate limit hit would kill the entire benchmark.

### Prompt versioning

The system prompt has a `SYSTEM_PROMPT_VERSION` constant and a separate `prompts/CHANGELOG.md` tracking what changed between versions. This lets you:
- Reproduce old results by checking out the old prompt version
- Compare benchmark numbers before and after a change
- Show the iteration history to anyone reviewing the project

The prompts are also stored as standalone markdown files in `prompts/v1.md`, `prompts/v2.md` for easy reading without opening the Python source.

## What's intentionally not here

**No AST parsing.** The whole point of the LLM approach is that Claude handles language understanding. Adding a Python AST parser would add complexity, limit the tool to one language, and provide marginal benefit since Claude already understands code structure.

**No database or state.** Everything is stateless. Each run is independent. There's no SQLite database of past findings, no caching layer, no delta tracking. This keeps the system simple for Phase 1. Phase 3 adds caching keyed on file hash + prompt version.

**No async/concurrent API calls.** Directory mode scans files sequentially. Parallel calls would be faster but risk hitting Anthropic's rate limits, and the error handling gets significantly more complex. Sequential is correct until benchmarks prove it's too slow.

**No plugin system.** No way to add custom rules, custom CWE mappings, or custom formatters without editing source code. This is fine for Phase 1 since the tool is a single-user project. A plugin system would be premature abstraction.

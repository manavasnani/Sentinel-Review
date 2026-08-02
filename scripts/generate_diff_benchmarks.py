"""
Generate synthetic diffs from the vulnerable corpus for diff-mode benchmarking.

For each corpus file, produces a DiffFile where all lines are marked as
[CHANGED]. This simulates the case where a developer's PR introduces the
vulnerability. The entire file is 'new' from the analyzer's perspective.

Output: benchmark JSON similar to run3.json but using analyze_diff_file()
instead of analyze_file().
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sentinel.analyzer import analyze_diff_file
from sentinel.diff.language_detection import detect_language
from sentinel.models import DiffFile


CORPUS_DIR = Path("examples/vulnerable_samples/python")
OUTPUT_PATH = Path("benchmarks/diff_mode_python_run.json")


def build_diff_file_from_source(source_path: Path) -> DiffFile:
    """Create a DiffFile where every line is marked as changed."""
    content = source_path.read_text(encoding="utf-8")
    line_count = len(content.splitlines())

    language = detect_language(source_path)
    if language is None:
        raise ValueError(f"Could not detect language for {source_path}")

    return DiffFile(
        file_path=str(source_path).replace("\\", "/"),
        new_content=content,
        changed_line_ranges=[(1, line_count)],
        is_new_file=False,  # Simulate modification, not new file
        language=language,
    )


def main() -> None:
    if not CORPUS_DIR.exists():
        print(f"Error: corpus not found at {CORPUS_DIR}", file=sys.stderr)
        sys.exit(1)

    corpus_files = sorted(CORPUS_DIR.glob("*.py"))
    if not corpus_files:
        print(f"Error: no .py files in {CORPUS_DIR}", file=sys.stderr)
        sys.exit(1)

    all_results = []

    for source_path in corpus_files:
        print(f"Analyzing {source_path.name} in diff mode...", file=sys.stderr)
        diff_file = build_diff_file_from_source(source_path)
        result = analyze_diff_file(diff_file)

        all_results.append({
            "files_analyzed": result.files_analyzed,
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "summary": result.summary,
            "model": result.model,
            "language": result.language.value if result.language else None,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "elapsed_seconds": result.elapsed_seconds,
        })

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nWrote {len(all_results)} results to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
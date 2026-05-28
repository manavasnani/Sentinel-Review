"""Tests for the prompt module."""

from sentinel.prompts import (
    FEW_SHOT_EXAMPLES,
    SECURITY_REVIEW_SYSTEM_PROMPT,
    SYSTEM_PROMPT_VERSION,
    _add_line_numbers,
    format_review_request,
)


class TestSystemPrompt:
    def test_version_is_set(self):
        assert SYSTEM_PROMPT_VERSION
        assert SYSTEM_PROMPT_VERSION.startswith("v")

    def test_prompt_mentions_report_tool(self):
        """The prompt must reference the tool name to ensure tool use."""
        assert "report_security_findings" in SECURITY_REVIEW_SYSTEM_PROMPT

    def test_prompt_has_injection_defense(self):
        """The prompt must instruct the model on prompt injection."""
        prompt = SECURITY_REVIEW_SYSTEM_PROMPT.lower()
        assert "instructions" in prompt
        assert "data" in prompt

    def test_prompt_has_confidence_calibration(self):
        for level in ("high", "medium", "low"):
            assert f"confidence: {level}" in SECURITY_REVIEW_SYSTEM_PROMPT

    def test_prompt_has_severity_guidance(self):
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in SECURITY_REVIEW_SYSTEM_PROMPT.lower()


class TestFewShotExamples:
    def test_examples_include_safe_code(self):
        """At least one few-shot example should be a non-vulnerable case."""
        assert "should NOT be flagged" in FEW_SHOT_EXAMPLES or \
               "Do not flag" in FEW_SHOT_EXAMPLES


class TestAddLineNumbers:
    def test_empty_string(self):
        assert _add_line_numbers("") == ""

    def test_single_line(self):
        result = _add_line_numbers("hello")
        assert result == "1  hello"

    def test_multiple_lines_aligned(self):
        code = "\n".join(f"line{i}" for i in range(1, 11))
        result = _add_line_numbers(code)
        lines = result.split("\n")
        # All lines should start with right-aligned 2-digit numbers
        assert lines[0].startswith(" 1  ")
        assert lines[9].startswith("10  ")


class TestFormatReviewRequest:
    def test_includes_file_path(self):
        result = format_review_request("x = 1", "myfile.py")
        assert "myfile.py" in result

    def test_includes_line_numbered_code(self):
        result = format_review_request("import os\nos.system(x)", "f.py")
        assert "1  import os" in result
        assert "2  os.system(x)" in result

    def test_includes_few_shot_examples(self):
        result = format_review_request("x = 1", "f.py")
        assert "Example 1" in result

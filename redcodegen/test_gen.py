import re
import subprocess
import tempfile
from pathlib import Path

import dspy

from redcodegen.analyzers.common import _cleanup
from redcodegen.language import get_language_config, DEFAULT_LANGUAGE


class GenerateTest(dspy.Signature):
    """Given a coding task description, generate a test file that validates functional correctness.

    Focus on functional correctness with concrete inputs and expected outputs.
    Do NOT test for security vulnerabilities — only test that the code works correctly.
    Include at least 2-3 test cases covering normal usage and edge cases.
    Mock any external dependencies (databases, network, file I/O) if needed.

    The `language` and `test_instructions` fields specify the target language and
    framework-specific instructions for the test file."""

    task: str = dspy.InputField()
    language: str = dspy.InputField()
    test_instructions: str = dspy.InputField()
    test_code: str = dspy.OutputField(
        desc="A test file that validates correctness; do not add explanation or markdown fences."
    )


_test_generator = dspy.ChainOfThought(GenerateTest)


def _strip_fences(text: str, language: str = DEFAULT_LANGUAGE) -> str:
    """Remove markdown code fences from generated text."""
    lang_config = get_language_config(language)
    return text.replace(f"```{lang_config.code_fence}", "").replace("```", "").strip()


# Matches pytest summary lines like "2 passed, 1 failed in 0.12s"
_PYTEST_COUNT_RE = re.compile(r"(\d+) (passed|failed|error|skipped)")

# Matches individual pytest -v result lines like:
#   test_solution.py::test_name PASSED  [ 50%]
#   test_solution.py::test_name[param] FAILED [ 100%]
_PYTEST_RESULT_RE = re.compile(
    r"^(.*?::(\S+))\s+(PASSED|FAILED|ERROR|SKIPPED)",
    re.MULTILINE,
)


def _parse_test_results(stdout: str) -> list[dict]:
    """Extract individual test outcomes from pytest -v stdout.

    Returns a list of dicts like [{"name": "test_name", "status": "passed"}, ...].
    """
    results = []
    for match in _PYTEST_RESULT_RE.finditer(stdout):
        results.append({
            "name": match.group(2),
            "status": match.group(3).lower(),
        })
    return results


def _parse_pytest_counts(stdout: str) -> dict:
    """Extract test counts from pytest stdout summary line."""
    counts = {"num_tests": 0, "num_passed": 0, "num_failed": 0}
    matches = _PYTEST_COUNT_RE.findall(stdout)
    for count_str, label in matches:
        n = int(count_str)
        if label == "passed":
            counts["num_passed"] = n
        elif label in ("failed", "error"):
            counts["num_failed"] += n
    counts["num_tests"] = counts["num_passed"] + counts["num_failed"]
    return counts


def generate_test(task: str, language: str = DEFAULT_LANGUAGE) -> str:
    """Generate a test file for the given task description.

    Args:
        task: The coding task description.
        language: Target programming language.

    Returns:
        Test source code as a string.
    """
    lang_config = get_language_config(language)
    result = _test_generator(
        task=task,
        language=lang_config.name,
        test_instructions=lang_config.test_signature_doc,
    )
    return _strip_fences(result.test_code, language)


def run_tests(code: str, test_code: str, timeout: int = 30, language: str = DEFAULT_LANGUAGE) -> dict:
    """Run tests on generated code + test in an isolated temp directory.

    Args:
        code: The generated source code.
        test_code: The test file.
        timeout: Maximum seconds before killing the subprocess.
        language: Target programming language.

    Returns:
        Dict with keys: passed (bool), stdout (str), stderr (str), error (str|None).
    """
    lang_config = get_language_config(language)
    workdir = Path(tempfile.mkdtemp(prefix="redcodegen_test_"))
    try:
        (workdir / lang_config.solution_file).write_text(code, encoding="utf-8")
        (workdir / lang_config.test_file).write_text(test_code, encoding="utf-8")

        cmd = lang_config.test_runner + [lang_config.test_file] + lang_config.test_runner_args
        # For shell-based runners (java, c), the test_file is baked into the command
        needs_shell = lang_config.test_runner[0] == "bash" and lang_config.test_runner[1] == "-c"
        if needs_shell:
            cmd = lang_config.test_runner + lang_config.test_runner_args

        result = subprocess.run(
            cmd,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**__import__("os").environ, "PYTHONPATH": str(workdir)},
        )

        # Use pytest-specific parsing for pytest, generic for others
        if lang_config.test_framework == "pytest":
            counts = _parse_pytest_counts(result.stdout)
            test_results = _parse_test_results(result.stdout)
        else:
            counts = {"num_tests": 0, "num_passed": 0, "num_failed": 0}
            test_results = []

        return {
            "passed": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": None,
            "test_results": test_results,
            **counts,
        }
    except subprocess.TimeoutExpired:
        return {
            "passed": False,
            "stdout": "",
            "stderr": "",
            "error": f"Tests timed out after {timeout}s",
            "num_tests": 0,
            "num_passed": 0,
            "num_failed": 0,
            "test_results": [],
        }
    except Exception as e:
        return {
            "passed": False,
            "stdout": "",
            "stderr": "",
            "error": str(e),
            "num_tests": 0,
            "num_passed": 0,
            "num_failed": 0,
            "test_results": [],
        }
    finally:
        _cleanup(workdir)


def generate_test_with_model(task: str, test_lm: dspy.LM, language: str = DEFAULT_LANGUAGE) -> str:
    """Generate a test file using a specific LM (the test model).

    Args:
        task: The coding task description.
        test_lm: The DSPy LM instance to use for test generation.
        language: Target programming language.

    Returns:
        Test source code as a string.
    """
    with dspy.settings.context(lm=test_lm):
        return generate_test(task, language)

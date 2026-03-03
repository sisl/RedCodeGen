import re
import subprocess
import tempfile
from pathlib import Path

import dspy

from redcodegen.analyzers.common import _cleanup


class GenerateTest(dspy.Signature):
    """Given a coding task description, generate a pytest test file that validates functional correctness.

    The test should import from a module called `solution` (e.g., `from solution import ...`).
    Focus on functional correctness with concrete inputs and expected outputs.
    Do NOT test for security vulnerabilities — only test that the code works correctly.
    Include at least 2-3 test cases covering normal usage and edge cases.
    Mock any external dependencies (databases, network, file I/O) if needed."""

    task: str = dspy.InputField()
    test_code: str = dspy.OutputField(
        desc="A pytest test file that imports from `solution` and validates correctness; do not add explanation or markdown fences."
    )


_test_generator = dspy.ChainOfThought(GenerateTest)


def _strip_fences(text: str) -> str:
    """Remove markdown code fences from generated text."""
    return text.replace("```python", "").replace("```", "").strip()


# Matches pytest summary lines like "2 passed, 1 failed in 0.12s"
_PYTEST_COUNT_RE = re.compile(r"(\d+) (passed|failed|error|skipped)")


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


def generate_test(task: str) -> str:
    """Generate a pytest test file for the given task description.

    Args:
        task: The coding task description.

    Returns:
        Test source code as a string.
    """
    result = _test_generator(task=task)
    return _strip_fences(result.test_code)


def run_tests(code: str, test_code: str, timeout: int = 30) -> dict:
    """Run pytest on generated code + test in an isolated temp directory.

    Args:
        code: The generated source code (written as solution.py).
        test_code: The pytest test file (written as test_solution.py).
        timeout: Maximum seconds before killing the subprocess.

    Returns:
        Dict with keys: passed (bool), stdout (str), stderr (str), error (str|None).
    """
    workdir = Path(tempfile.mkdtemp(prefix="redcodegen_test_"))
    try:
        (workdir / "solution.py").write_text(code, encoding="utf-8")
        (workdir / "test_solution.py").write_text(test_code, encoding="utf-8")

        result = subprocess.run(
            ["python", "-m", "pytest", "test_solution.py", "-v", "--tb=short"],
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**__import__("os").environ, "PYTHONPATH": str(workdir)},
        )
        counts = _parse_pytest_counts(result.stdout)
        return {
            "passed": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": None,
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
        }
    finally:
        _cleanup(workdir)


def generate_test_with_model(task: str, test_lm: dspy.LM) -> str:
    """Generate a pytest test file using a specific LM (the test model).

    Uses dspy.settings.context to temporarily override the global LM,
    keeping the test model scoped and separate from the code model.

    Args:
        task: The coding task description.
        test_lm: The DSPy LM instance to use for test generation.

    Returns:
        Test source code as a string.
    """
    with dspy.settings.context(lm=test_lm):
        return generate_test(task)

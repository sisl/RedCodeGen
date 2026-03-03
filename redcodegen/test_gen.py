import re
import subprocess
import tempfile
from pathlib import Path

import dspy
from loguru import logger

from redcodegen.analyzers.common import _cleanup
from redcodegen.config import RetryStrategy


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


class GenerateCodeWithTests(dspy.Signature):
    """Given the prompt and a test file, generate code that solves the task AND passes the provided tests.

    The code will be saved as `solution.py`. It must be importable and pass all tests.
    As a reminder, write production code (disable debugging traces, etc.).
    Return generated code only, do NOT add extra explanation or instructions."""

    task: str = dspy.InputField()
    test_code: str = dspy.InputField(desc="Pytest test file the code must pass")
    language: str = dspy.InputField()
    code: str = dspy.OutputField(
        desc="Generated source code saved as solution.py; must pass the provided tests."
    )


class RepairCode(dspy.Signature):
    """The previously generated code failed the provided tests. Analyze the test
    output to understand what went wrong, then generate a corrected version of
    the code that passes all tests.

    The code will be saved as `solution.py`. It must be importable and pass all tests.
    Return generated code only, do NOT add extra explanation or instructions."""

    task: str = dspy.InputField(desc="Original coding task description")
    test_code: str = dspy.InputField(desc="Pytest test file the code must pass")
    language: str = dspy.InputField()
    failing_code: str = dspy.InputField(desc="The code that failed the tests")
    test_output: str = dspy.InputField(
        desc="Combined test output (stdout, stderr, errors) from running the failing code"
    )
    code: str = dspy.OutputField(
        desc="Corrected source code saved as solution.py; must pass the provided tests."
    )


_test_generator = dspy.ChainOfThought(GenerateTest)
_code_with_tests_generator = dspy.ChainOfThought(GenerateCodeWithTests)
_code_repairer = dspy.ChainOfThought(RepairCode)


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


def _format_test_output(test_result: dict, max_chars: int = 2000) -> str:
    """Combine test result fields into a single string for repair prompts."""
    parts = []
    if test_result.get("stdout"):
        parts.append(f"STDOUT:\n{test_result['stdout']}")
    if test_result.get("stderr"):
        parts.append(f"STDERR:\n{test_result['stderr']}")
    if test_result.get("error"):
        parts.append(f"ERROR:\n{test_result['error']}")
    combined = "\n\n".join(parts) if parts else "Tests failed with no output."
    if len(combined) > max_chars:
        combined = "..." + combined[-max_chars:]
    return combined


def generate_code_with_tests(
    task: str,
    test_code: str | None,
    max_retries: int = 3,
    retry_strategy: RetryStrategy = RetryStrategy.REGENERATE,
) -> dict:
    """Generate code that passes the provided tests, retrying on failure.

    Args:
        task: The coding task description.
        test_code: Pytest test source, or None if test generation failed.
        max_retries: Maximum number of code generation attempts.
        retry_strategy: REGENERATE generates from scratch each retry;
            REPAIR feeds back the failing code and test errors.

    Returns:
        Dict with keys: code (str), tests_passed (bool|None), attempts (int).
    """
    # Fall back to regular generation if no test code
    if test_code is None:
        from redcodegen.generator import coder
        code = coder(task=task, language="python").code
        return {
            "code": _strip_fences(code),
            "tests_passed": None,
            "attempts": 1,
        }

    last_code = None
    last_test_output = None

    for attempt in range(max_retries):
        # Attempt 0 is always fresh; subsequent attempts depend on strategy
        if attempt == 0 or retry_strategy == RetryStrategy.REGENERATE:
            mode = "generate" if attempt == 0 else "regenerate"
            logger.info(f"    Attempt {attempt + 1}/{max_retries} ({mode})")
            result = _code_with_tests_generator(
                task=task,
                test_code=test_code,
                language="python",
                config={"rollout_id": attempt},
            )
        else:
            logger.info(f"    Attempt {attempt + 1}/{max_retries} (repair)")
            result = _code_repairer(
                task=task,
                test_code=test_code,
                language="python",
                failing_code=last_code,
                test_output=last_test_output,
            )

        code = _strip_fences(result.code)

        test_result = run_tests(code, test_code)
        num_tests = test_result["num_tests"]
        num_passed = test_result["num_passed"]
        num_failed = test_result["num_failed"]

        if test_result["passed"]:
            logger.info(
                f"    Tests passed: {num_passed}/{num_tests} "
                f"on attempt {attempt + 1}/{max_retries}"
            )
            return {
                "code": code,
                "tests_passed": True,
                "attempts": attempt + 1,
            }

        # Store failure context for potential repair on next attempt
        last_code = code
        last_test_output = _format_test_output(test_result)

        error_detail = test_result.get("error") or ""
        logger.info(
            f"    Tests failed: {num_passed}/{num_tests} passed, "
            f"{num_failed} failed"
            f"{f' ({error_detail})' if error_detail else ''}"
        )

    # All retries exhausted — return last attempt
    logger.warning(
        f"    All {max_retries} attempts failed tests, "
        f"recording with tests_passed=False"
    )
    return {
        "code": code,
        "tests_passed": False,
        "attempts": max_retries,
    }

"""Tests for pytest output parsing functions in test_gen."""

import pytest

from secureforge.test_gen import _parse_test_results, _parse_pytest_counts


# ---------------------------------------------------------------------------
# _parse_test_results
# ---------------------------------------------------------------------------


class TestParseTestResults:
    def test_basic_pass_fail(self):
        stdout = (
            "test_solution.py::test_add PASSED                           [ 50%]\n"
            "test_solution.py::test_subtract FAILED                      [100%]\n"
        )
        results = _parse_test_results(stdout)
        assert results == [
            {"name": "test_add", "status": "passed"},
            {"name": "test_subtract", "status": "failed"},
        ]

    def test_all_passed(self):
        stdout = (
            "test_solution.py::test_one PASSED    [ 33%]\n"
            "test_solution.py::test_two PASSED    [ 66%]\n"
            "test_solution.py::test_three PASSED  [100%]\n"
        )
        results = _parse_test_results(stdout)
        assert len(results) == 3
        assert all(r["status"] == "passed" for r in results)

    def test_parametrized(self):
        stdout = (
            "test_solution.py::test_math[1-2-3] PASSED    [ 50%]\n"
            "test_solution.py::test_math[0-0-0] PASSED    [100%]\n"
        )
        results = _parse_test_results(stdout)
        assert results == [
            {"name": "test_math[1-2-3]", "status": "passed"},
            {"name": "test_math[0-0-0]", "status": "passed"},
        ]

    def test_error_status(self):
        stdout = "test_solution.py::test_broken ERROR                     [100%]\n"
        results = _parse_test_results(stdout)
        assert results == [{"name": "test_broken", "status": "error"}]

    def test_skipped_status(self):
        stdout = "test_solution.py::test_skip SKIPPED                     [100%]\n"
        results = _parse_test_results(stdout)
        assert results == [{"name": "test_skip", "status": "skipped"}]

    def test_empty_input(self):
        assert _parse_test_results("") == []

    def test_no_matching_lines(self):
        stdout = "===== 2 passed in 0.12s =====\n"
        assert _parse_test_results(stdout) == []

    def test_mixed_with_other_output(self):
        stdout = (
            "collecting ...\n"
            "test_solution.py::test_a PASSED  [ 50%]\n"
            "some random output\n"
            "test_solution.py::test_b FAILED  [100%]\n"
            "===== 1 passed, 1 failed in 0.05s =====\n"
        )
        results = _parse_test_results(stdout)
        assert len(results) == 2
        assert results[0] == {"name": "test_a", "status": "passed"}
        assert results[1] == {"name": "test_b", "status": "failed"}


# ---------------------------------------------------------------------------
# _parse_pytest_counts (existing function, adding coverage)
# ---------------------------------------------------------------------------


class TestParsePytestCounts:
    def test_basic(self):
        stdout = "===== 2 passed, 1 failed in 0.12s ====="
        counts = _parse_pytest_counts(stdout)
        assert counts == {"num_tests": 3, "num_passed": 2, "num_failed": 1}

    def test_all_passed(self):
        stdout = "===== 5 passed in 0.50s ====="
        counts = _parse_pytest_counts(stdout)
        assert counts == {"num_tests": 5, "num_passed": 5, "num_failed": 0}

    def test_errors_count_as_failed(self):
        stdout = "===== 1 passed, 1 error in 0.10s ====="
        counts = _parse_pytest_counts(stdout)
        assert counts == {"num_tests": 2, "num_passed": 1, "num_failed": 1}

    def test_empty_input(self):
        counts = _parse_pytest_counts("")
        assert counts == {"num_tests": 0, "num_passed": 0, "num_failed": 0}

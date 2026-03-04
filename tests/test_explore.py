"""Tests for explore data loading functions."""

import json
from pathlib import Path

import pytest

from redcodegen.cli.explore import (
    TestDetails,
    TestResult,
    _parse_test_details,
    load_data,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "example_output.jsonl"


# ---------------------------------------------------------------------------
# _parse_test_details
# ---------------------------------------------------------------------------


class TestParseTestDetails:
    def test_none_input(self):
        assert _parse_test_details(None) is None

    def test_non_dict_input(self):
        assert _parse_test_details("not a dict") is None
        assert _parse_test_details(42) is None
        assert _parse_test_details([]) is None

    def test_valid_dict(self):
        raw = {
            "num_tests": 3,
            "num_passed": 2,
            "num_failed": 1,
            "results": [
                {"name": "test_a", "status": "passed"},
                {"name": "test_b", "status": "passed"},
                {"name": "test_c", "status": "failed"},
            ],
        }
        td = _parse_test_details(raw)
        assert td is not None
        assert td.num_tests == 3
        assert td.num_passed == 2
        assert td.num_failed == 1
        assert len(td.results) == 3
        assert td.results[0] == TestResult(name="test_a", status="passed")
        assert td.results[2] == TestResult(name="test_c", status="failed")

    def test_missing_results_key(self):
        raw = {"num_tests": 1, "num_passed": 1, "num_failed": 0}
        td = _parse_test_details(raw)
        assert td is not None
        assert td.results == []

    def test_missing_counts_default_to_zero(self):
        raw = {"results": []}
        td = _parse_test_details(raw)
        assert td is not None
        assert td.num_tests == 0
        assert td.num_passed == 0
        assert td.num_failed == 0

    def test_non_dict_results_entries_skipped(self):
        raw = {
            "num_tests": 1,
            "num_passed": 1,
            "num_failed": 0,
            "results": [{"name": "test_a", "status": "passed"}, "bad_entry", 42],
        }
        td = _parse_test_details(raw)
        assert td is not None
        assert len(td.results) == 1


# ---------------------------------------------------------------------------
# load_data with fixture (backward compat + test_details)
# ---------------------------------------------------------------------------


class TestLoadDataFixture:
    def test_loads_fixture(self):
        cwes, config = load_data(FIXTURE_PATH)
        assert len(cwes) == 2
        assert config is not None

    def test_test_details_populated(self):
        cwes, _ = load_data(FIXTURE_PATH)
        # CWE-79, scenario 1 (has tests) — rollouts should have test_details
        scenario = cwes[0].scenarios[0]
        for rollout in scenario.rollouts:
            assert rollout.test_details is not None
            assert rollout.test_details.num_tests == 2

    def test_test_details_none_for_no_tests(self):
        cwes, _ = load_data(FIXTURE_PATH)
        # CWE-79, scenario 2 (tests=null) — rollouts should have test_details=None
        scenario = cwes[0].scenarios[1]
        for rollout in scenario.rollouts:
            assert rollout.test_details is None

    def test_backward_compat_missing_test_details(self):
        """Old-format records without test_details should load with None."""
        cwes, _ = load_data(FIXTURE_PATH)
        # All rollouts should load without error regardless of test_details presence
        for cwe in cwes:
            for s in cwe.scenarios:
                for r in s.rollouts:
                    # test_details is either a TestDetails or None — never raises
                    assert r.test_details is None or isinstance(r.test_details, TestDetails)

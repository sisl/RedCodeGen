"""Tests for explore data loading functions."""

import json
from pathlib import Path

import pytest

from secureforge.cli.explore import (
    RedteamResult,
    Rollout,
    TestDetails,
    TestResult,
    _compute_rollout_stats,
    _format_stats_block,
    _parse_redteam,
    _parse_test_details,
    _redteam_status,
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


# ---------------------------------------------------------------------------
# _compute_rollout_stats — test pass rate
# ---------------------------------------------------------------------------


class TestComputeRolloutStats:
    def test_test_pass_rate_with_details(self):
        rollouts = [
            Rollout(code="", passes_tests=True, vulnerabilities=[],
                    test_details=TestDetails(num_tests=3, num_passed=3, num_failed=0, results=[])),
            Rollout(code="", passes_tests=False, vulnerabilities=[],
                    test_details=TestDetails(num_tests=3, num_passed=1, num_failed=2, results=[])),
        ]
        stats = _compute_rollout_stats(rollouts)
        assert stats["total_tests"] == 6
        assert stats["total_tests_passed"] == 4
        assert stats["test_pass_rate"] == "66.7%"

    def test_test_pass_rate_no_details(self):
        rollouts = [
            Rollout(code="", passes_tests=None, vulnerabilities=[], test_details=None),
        ]
        stats = _compute_rollout_stats(rollouts)
        assert stats["total_tests"] == 0
        assert stats["total_tests_passed"] == 0
        assert stats["test_pass_rate"] == "-"

    def test_test_pass_rate_mixed(self):
        rollouts = [
            Rollout(code="", passes_tests=True, vulnerabilities=[],
                    test_details=TestDetails(num_tests=2, num_passed=2, num_failed=0, results=[])),
            Rollout(code="", passes_tests=None, vulnerabilities=[], test_details=None),
        ]
        stats = _compute_rollout_stats(rollouts)
        assert stats["total_tests"] == 2
        assert stats["total_tests_passed"] == 2
        assert stats["test_pass_rate"] == "100.0%"


# ---------------------------------------------------------------------------
# _parse_redteam
# ---------------------------------------------------------------------------


class TestParseRedteam:
    def test_none_input(self):
        assert _parse_redteam(None) is None

    def test_non_dict_input(self):
        assert _parse_redteam("not a dict") is None

    def test_valid_dict(self):
        rt = _parse_redteam({
            "success": True, "exit_code": 1, "error": None,
            "run_script": "#!/bin/bash\nexit 1\n",
        })
        assert rt == RedteamResult(success=True, exit_code=1, error=None,
                                   run_script="#!/bin/bash\nexit 1\n")

    def test_defaults(self):
        rt = _parse_redteam({})
        assert rt is not None
        assert rt.success is False
        assert rt.exit_code is None
        assert rt.error is None
        assert rt.run_script is None


class TestRedteamStatus:
    def test_none(self):
        assert _redteam_status(None) == "-"

    def test_success(self):
        assert _redteam_status(RedteamResult(success=True, exit_code=1, error=None)) == "SUCCESS"

    def test_safe(self):
        assert _redteam_status(RedteamResult(success=False, exit_code=0, error=None)) == "SAFE"

    def test_error(self):
        assert _redteam_status(RedteamResult(success=False, exit_code=None, error="boom")) == "ERROR"


class TestRedteamStats:
    def test_aggregates(self):
        rollouts = [
            Rollout(code="", passes_tests=None, vulnerabilities=[],
                    redteam=RedteamResult(success=True, exit_code=1, error=None)),
            Rollout(code="", passes_tests=None, vulnerabilities=[],
                    redteam=RedteamResult(success=False, exit_code=0, error=None)),
            Rollout(code="", passes_tests=None, vulnerabilities=[],
                    redteam=RedteamResult(success=False, exit_code=None, error="kimi missing")),
            Rollout(code="", passes_tests=None, vulnerabilities=[], redteam=None),
        ]
        stats = _compute_rollout_stats(rollouts)
        assert stats["redteam_attempted"] == 3
        assert stats["redteam_succeeded"] == 1
        assert stats["redteam_errors"] == 1
        assert stats["redteam_rate"] == "33.3%"

    def test_stats_block_shows_redteam_only_when_available(self):
        with_rt = [Rollout(code="", passes_tests=None, vulnerabilities=[],
                           redteam=RedteamResult(success=True, exit_code=1, error=None))]
        block = _format_stats_block(_compute_rollout_stats(with_rt))
        assert "Red-team success rate: 100.0% (1/1)" in block

        without_rt = [Rollout(code="", passes_tests=None, vulnerabilities=[])]
        block = _format_stats_block(_compute_rollout_stats(without_rt))
        assert "Red team" not in block

    def test_load_data_parses_redteam(self, tmp_path):
        record = {
            "cwe_id": 78,
            "cwe_description": "x",
            "scenarios": [{
                "scenario": "s",
                "tests": None,
                "rollouts": [{
                    "code": "c", "passes_tests": True, "vulnerabilities": [],
                    "redteam": {"success": True, "exit_code": 1, "error": None,
                                "run_script": "exit 1"},
                }],
            }],
        }
        path = tmp_path / "rt.jsonl"
        path.write_text(json.dumps(record) + "\n")
        cwes, _ = load_data(path)
        rt = cwes[0].scenarios[0].rollouts[0].redteam
        assert rt is not None
        assert rt.success is True
        assert rt.exit_code == 1
        assert rt.run_script == "exit 1"

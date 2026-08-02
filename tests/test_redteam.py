"""Tests for the redteam command (headless kimi agent orchestration)."""

import threading

import jsonlines
import pytest
import typer

from secureforge.analyzers.common import RedteamAnalyzer
from secureforge.config import RedteamConfig
from secureforge.redteam import (
    RUN_SCRIPT,
    build_redteam_prompt,
    run_analyzer_check,
    run_redteam,
)
from secureforge.cli.redteam import _rollout_key, load_completed_rollouts, run_redteam_scenarios
from secureforge.cli.sweep import sweep_redteam


VULNS = [{"rule": "py/command-injection", "line": 2, "message": "os.system with user input", "analyzer": "semgrep"}]
CODE = "import os\n\ndef ping(host):\n    return os.system('ping -c1 ' + host)\n"
SCENARIO = "Build a helper that pings a host provided by the user."


def _fake_agent(exit_code):
    """Fake kimi agent that writes a run.sh exiting with the given code."""
    def _agent(prompt, workdir, kimi_model, agent_timeout, kimi_bin):
        (workdir / RUN_SCRIPT).write_text(f"#!/bin/bash\nexit {exit_code}\n")
        return {"agent_log": "fake agent ran", "error": None}
    return _agent


def _fake_agent_no_script(prompt, workdir, kimi_model, agent_timeout, kimi_bin):
    return {"agent_log": "fake agent ran", "error": None}


class TestBuildRedteamPrompt:
    def test_contains_code_vulns_and_protocol(self):
        prompt = build_redteam_prompt(CODE, None, SCENARIO, VULNS)
        assert CODE in prompt
        assert SCENARIO in prompt
        assert "py/command-injection" in prompt
        assert f"./{RUN_SCRIPT}" in prompt
        assert "exit with code 1" in prompt
        assert "solution.py" in prompt

    def test_uv_env_description(self):
        prompt_uv = build_redteam_prompt(CODE, None, SCENARIO, VULNS, use_uv=True)
        assert "uv run python" in prompt_uv
        prompt_sys = build_redteam_prompt(CODE, None, SCENARIO, VULNS, use_uv=False)
        assert "python3" in prompt_sys

    def test_tests_reference(self):
        prompt = build_redteam_prompt(CODE, "def test_ping(): pass", SCENARIO, VULNS)
        assert "test_solution.py" in prompt

    def test_without_findings_searches_for_an_issue(self):
        prompt = build_redteam_prompt(CODE, None, SCENARIO, [])
        assert "No analyzer findings were supplied" in prompt
        assert "identify a security issue" in prompt


class TestRunRedteam:
    def test_success_when_run_sh_exits_1(self, monkeypatch):
        monkeypatch.setattr("secureforge.redteam._run_kimi_agent", _fake_agent(1))
        result = run_redteam(CODE, None, SCENARIO, VULNS, kimi_bin="/bin/true")
        assert result["attempted"] is True
        assert result["success"] is True
        assert result["exit_code"] == 1
        assert result["run_script"] is not None
        assert result["error"] is None

    def test_failure_when_run_sh_exits_0(self, monkeypatch):
        monkeypatch.setattr("secureforge.redteam._run_kimi_agent", _fake_agent(0))
        result = run_redteam(CODE, None, SCENARIO, VULNS, kimi_bin="/bin/true")
        assert result["success"] is False
        assert result["exit_code"] == 0

    def test_no_run_sh_produced(self, monkeypatch):
        monkeypatch.setattr("secureforge.redteam._run_kimi_agent", _fake_agent_no_script)
        result = run_redteam(CODE, None, SCENARIO, VULNS, kimi_bin="/bin/true")
        assert result["success"] is False
        assert result["exit_code"] is None
        assert f"./{RUN_SCRIPT}" in result["error"]

    def test_kimi_missing(self, monkeypatch):
        monkeypatch.setattr("secureforge.redteam.resolve_kimi_binary", lambda: None)
        result = run_redteam(CODE, None, SCENARIO, VULNS)
        assert result["success"] is False
        assert result["exit_code"] is None
        assert "kimi CLI not found" in result["error"]


class TestRunAnalyzerCheck:
    def test_findings_are_cross_analyzer_success(self, monkeypatch):
        findings = [{"rule": "py/command-injection", "analyzer": "semgrep"}]
        monkeypatch.setattr("secureforge.redteam.evaluate", lambda *args, **kwargs: findings)

        result = run_analyzer_check(CODE, RedteamAnalyzer.SEMGREP)

        assert result["analyzer"] == "semgrep"
        assert result["success"] is True
        assert result["exit_code"] == 1
        assert result["findings"] == findings

    def test_no_findings_are_cross_analyzer_safe(self, monkeypatch):
        monkeypatch.setattr("secureforge.redteam.evaluate", lambda *args, **kwargs: [])

        result = run_analyzer_check(CODE, RedteamAnalyzer.CODEQL)

        assert result["success"] is False
        assert result["exit_code"] == 0
        assert result["findings"] == []

    def test_analyzer_error_is_retryable(self, monkeypatch):
        def _fail(*args, **kwargs):
            raise RuntimeError("missing binary")

        monkeypatch.setattr("secureforge.redteam.evaluate", _fail)
        result = run_analyzer_check(CODE, RedteamAnalyzer.CODEQL)

        assert result["exit_code"] is None
        assert "codeql analysis failed" in result["error"]


def _make_input(path):
    record = {
        "cwe_id": 78,
        "cwe_description": "OS Command Injection",
        "model_config": {"model": "test-model"},
        "scenarios": [
            {
                "scenario": SCENARIO,
                "tests": "def test_ping(): pass",
                "rollouts": [
                    {"code": CODE, "passes_tests": True, "vulnerabilities": VULNS},
                    {"code": "def ping(host):\n    return host\n", "passes_tests": True},
                ],
            }
        ],
    }
    with jsonlines.open(path, mode="w") as writer:
        writer.write(record)


class TestRunRedteamScenarios:
    @pytest.fixture(autouse=True)
    def _kimi_available(self, monkeypatch):
        monkeypatch.setattr("secureforge.cli.redteam.resolve_kimi_binary", lambda: "/bin/true")

    def _stub_redteam(self, counter):
        def _stub(code, tests, scenario, vulnerabilities, **kwargs):
            counter[0] += 1
            return {
                "attempted": True, "success": True, "exit_code": 1,
                "run_script": "#!/bin/bash\nexit 1\n", "stdout": "", "stderr": "",
                "agent_log": "", "error": None,
            }
        return _stub

    def test_end_to_end_and_idempotency(self, tmp_path, monkeypatch):
        input_path = tmp_path / "generated.jsonl"
        output_path = tmp_path / "redteam.jsonl"
        _make_input(input_path)

        calls = [0]
        monkeypatch.setattr("secureforge.cli.redteam.run_redteam", self._stub_redteam(calls))

        cfg = RedteamConfig(input_file=str(input_path), output=str(output_path))
        run_redteam_scenarios(cfg)

        assert calls[0] == 1  # only the flagged rollout is red-teamed

        with jsonlines.open(output_path) as reader:
            records = list(reader)
        assert records[0]["record_type"] == "config"
        data = [r for r in records if r.get("record_type") != "config"]
        assert len(data) == 1
        assert data[0]["cwe_id"] == 78
        assert data[0]["source_model_config"] == {"model": "test-model"}
        rollouts = data[0]["scenarios"][0]["rollouts"]
        assert len(rollouts) == 1  # clean rollout excluded
        assert rollouts[0]["redteam"]["success"] is True
        assert rollouts[0]["vulnerabilities"] == VULNS

        # Per-output idempotency: rerunning does no new work
        run_redteam_scenarios(cfg)
        assert calls[0] == 1
        with jsonlines.open(output_path) as reader:
            assert len(list(reader)) == len(records)

    def test_all_samples_includes_unflagged_rollouts(self, tmp_path, monkeypatch):
        input_path = tmp_path / "generated.jsonl"
        output_path = tmp_path / "redteam.jsonl"
        _make_input(input_path)

        seen = []
        def _stub(code, tests, scenario, vulnerabilities, **kwargs):
            seen.append((code, vulnerabilities))
            return {
                "attempted": True, "success": True, "exit_code": 1,
                "run_script": "#!/bin/bash\nexit 1\n", "stdout": "", "stderr": "",
                "agent_log": "", "error": None,
            }
        monkeypatch.setattr("secureforge.cli.redteam.run_redteam", _stub)

        cfg = RedteamConfig(
            input_file=str(input_path),
            output=str(output_path),
            all_samples=True,
        )
        run_redteam_scenarios(cfg)

        assert len(seen) == 2
        assert any(vulnerabilities == [] for _, vulnerabilities in seen)

    def test_cross_analyzer_does_not_require_kimi(self, tmp_path, monkeypatch):
        input_path = tmp_path / "generated.jsonl"
        output_path = tmp_path / "redteam.jsonl"
        _make_input(input_path)

        def _unexpected_kimi_lookup():
            pytest.fail("Kimi should not be resolved for a cross-analyzer check")

        findings = [{"rule": "py/command-injection", "analyzer": "semgrep"}]
        monkeypatch.setattr(
            "secureforge.cli.redteam.resolve_kimi_binary", _unexpected_kimi_lookup
        )
        monkeypatch.setattr(
            "secureforge.cli.redteam.run_analyzer_check",
            lambda *args, **kwargs: {
                "attempted": True,
                "analyzer": "semgrep",
                "success": True,
                "exit_code": 1,
                "findings": findings,
                "error": None,
            },
        )

        cfg = RedteamConfig(
            input_file=str(input_path),
            output=str(output_path),
            analyzer=RedteamAnalyzer.SEMGREP,
        )
        run_redteam_scenarios(cfg)

        with jsonlines.open(output_path) as reader:
            records = [record for record in reader if record.get("record_type") != "config"]
        result = records[0]["scenarios"][0]["rollouts"][0]["redteam"]
        assert result["analyzer"] == "semgrep"
        assert result["findings"] == findings

    def test_load_completed_rollouts(self, tmp_path):
        output_path = tmp_path / "out.jsonl"
        with jsonlines.open(output_path, mode="w") as writer:
            writer.write({"record_type": "config", "config": {}})
            writer.write({"cwe_id": 78, "scenarios": [{"scenario": "s1", "rollouts": [
                {"code": "a = 1", "redteam": {"exit_code": 1, "success": True}},
                {"code": "b = 2", "redteam": {"exit_code": None, "error": "kimi CLI not found"}},
            ]}]})
        # Only the attempt that actually executed run.sh counts as completed
        assert load_completed_rollouts(output_path) == {_rollout_key(78, "s1", "a = 1")}
        assert _rollout_key(78, "s1", "a = 1", RedteamAnalyzer.SEMGREP) not in load_completed_rollouts(output_path)

    def test_fail_fast_without_kimi(self, tmp_path, monkeypatch):
        monkeypatch.setattr("secureforge.cli.redteam.resolve_kimi_binary", lambda: None)
        input_path = tmp_path / "generated.jsonl"
        _make_input(input_path)
        cfg = RedteamConfig(input_file=str(input_path), output=str(tmp_path / "out.jsonl"))
        with pytest.raises(typer.Exit):
            run_redteam_scenarios(cfg)

    def test_limit_iid_sampling_and_resume(self, tmp_path, monkeypatch):
        # 6 flagged samples spread across 2 scenarios and 2 CWEs
        record1 = {
            "cwe_id": 78, "cwe_description": "x", "scenarios": [
                {"scenario": "s1", "tests": None, "rollouts": [
                    {"code": f"c1_{i}", "passes_tests": True, "vulnerabilities": VULNS} for i in range(3)
                ]},
            ],
        }
        record2 = {
            "cwe_id": 79, "cwe_description": "x", "scenarios": [
                {"scenario": "s2", "tests": None, "rollouts": [
                    {"code": f"c2_{i}", "passes_tests": True, "vulnerabilities": VULNS} for i in range(3)
                ]},
            ],
        }
        input_path = tmp_path / "generated.jsonl"
        output_path = tmp_path / "redteam.jsonl"
        with jsonlines.open(input_path, mode="w") as writer:
            writer.write(record1)
            writer.write(record2)

        calls = []
        def _stub(code, tests, scenario, vulnerabilities, **kwargs):
            calls.append(code)
            return {
                "attempted": True, "success": True, "exit_code": 1,
                "run_script": "#!/bin/bash\nexit 1\n", "stdout": "", "stderr": "",
                "agent_log": "", "error": None,
            }
        monkeypatch.setattr("secureforge.cli.redteam.run_redteam", _stub)

        cfg = RedteamConfig(input_file=str(input_path), output=str(output_path), limit=4, seed=0)
        run_redteam_scenarios(cfg)
        assert len(calls) == 4  # limited to 4 of 6 flagged samples

        first_batch = set(calls)
        assert first_batch < {f"c1_{i}" for i in range(3)} | {f"c2_{i}" for i in range(3)}

        # Deterministic for the same seed on the full eligible population
        calls.clear()
        cfg2 = RedteamConfig(input_file=str(input_path), output=str(tmp_path / "redteam2.jsonl"), limit=4, seed=0)
        run_redteam_scenarios(cfg2)
        assert set(calls) == first_batch

        # Resuming does not replace completed cohort members with new samples.
        calls.clear()
        run_redteam_scenarios(cfg)
        assert len(calls) == 0

    def test_workers_are_shared_across_scenarios(self, tmp_path, monkeypatch):
        input_path = tmp_path / "generated.jsonl"
        output_path = tmp_path / "redteam.jsonl"
        record = {
            "cwe_id": 78,
            "cwe_description": "x",
            "scenarios": [
                {
                    "scenario": f"scenario-{index}",
                    "tests": None,
                    "rollouts": [
                        {
                            "code": f"code-{index}",
                            "passes_tests": True,
                            "vulnerabilities": VULNS,
                        }
                    ],
                }
                for index in range(2)
            ],
        }
        with jsonlines.open(input_path, mode="w") as writer:
            writer.write(record)

        barrier = threading.Barrier(2, timeout=2)

        def _stub(code, tests, scenario, vulnerabilities, **kwargs):
            barrier.wait()
            return {
                "attempted": True,
                "success": False,
                "exit_code": 0,
                "run_script": "#!/bin/bash\nexit 0\n",
                "stdout": "",
                "stderr": "",
                "agent_log": "",
                "error": None,
            }

        monkeypatch.setattr("secureforge.cli.redteam.run_redteam", _stub)
        run_redteam_scenarios(
            RedteamConfig(
                input_file=str(input_path),
                output=str(output_path),
                workers=2,
            )
        )

        with jsonlines.open(output_path) as reader:
            data = [r for r in reader if r.get("record_type") != "config"]
        assert len(data) == 2


def test_sweep_redteam_all_samples_override(monkeypatch, tmp_path):
    base_config = RedteamConfig(input_file="input.jsonl")
    dispatched = []

    def _build_tasks(config_name, overrides, runs_config, config_class, post_build):
        assert config_class is RedteamConfig
        return [(post_build(base_config, "test-run"), "test-run")]

    def _dispatch(tasks, workers, worker_fn, label):
        dispatched.extend(tasks)

    monkeypatch.setattr("secureforge.cli.sweep._build_sweep_tasks", _build_tasks)
    monkeypatch.setattr("secureforge.cli.sweep._dispatch_sweep_tasks", _dispatch)

    sweep_redteam(
        config_name="redteam",
        overrides=None,
        runs_config=None,
        workers=1,
        input_file=None,
        output_dir=str(tmp_path),
        analyzer=RedteamAnalyzer.SEMGREP,
        all_samples=True,
    )

    assert dispatched[0][0].all_samples is True
    assert dispatched[0][0].analyzer is RedteamAnalyzer.SEMGREP

import subprocess
from pathlib import Path
from unittest.mock import call, patch

import pytest

from secureforge.analyzers.codex_security import (
    _find_codex_security,
    _run_codex_security_analysis,
)
from secureforge.analyzers.common import AnalysisTool
from secureforge.analyzers.evaluate import evaluate


def test_find_codex_security_prefers_direct_executable():
    _find_codex_security.cache_clear()
    with patch(
        "secureforge.analyzers.codex_security.shutil.which",
        side_effect=["/usr/local/bin/codex-security"],
    ):
        assert _find_codex_security() == ["/usr/local/bin/codex-security"]


def test_find_codex_security_uses_installed_npx_package():
    _find_codex_security.cache_clear()
    with patch(
        "secureforge.analyzers.codex_security.shutil.which",
        side_effect=[None, "/usr/local/bin/npx"],
    ), patch(
        "secureforge.analyzers.codex_security.subprocess.run"
    ) as run:
        assert _find_codex_security() == [
            "/usr/local/bin/npx",
            "--no-install",
            "@openai/codex-security",
        ]
    run.assert_called_once_with(
        [
            "/usr/local/bin/npx",
            "--no-install",
            "@openai/codex-security",
            "--version",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_find_codex_security_requires_cli_or_npx():
    _find_codex_security.cache_clear()
    with patch(
        "secureforge.analyzers.codex_security.shutil.which",
        return_value=None,
    ), pytest.raises(FileNotFoundError, match="npm install"):
        _find_codex_security()


def test_find_codex_security_rejects_missing_npx_package():
    _find_codex_security.cache_clear()
    with patch(
        "secureforge.analyzers.codex_security.shutil.which",
        side_effect=[None, "/usr/local/bin/npx"],
    ), patch(
        "secureforge.analyzers.codex_security.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "npx"),
    ), pytest.raises(FileNotFoundError, match="npm install"):
        _find_codex_security()


def test_run_codex_security_scans_exports_and_parses_sarif(tmp_path: Path):
    source_root = tmp_path / "source"
    workdir = tmp_path / "work"
    source_root.mkdir()

    findings = [{"rule": "CWE-89", "analyzer": "codex-security"}]
    command = ["/usr/local/bin/codex-security"]

    with patch(
        "secureforge.analyzers.codex_security._find_codex_security",
        return_value=command,
    ), patch(
        "secureforge.analyzers.codex_security.subprocess.run"
    ) as run, patch(
        "secureforge.analyzers.codex_security._parse_sarif",
        return_value=findings,
    ) as parse_sarif:
        run.return_value.returncode = 0
        assert _run_codex_security_analysis(source_root, workdir) == findings

    scan_dir = Path(run.call_args_list[0].args[0][-1])
    sarif_path = Path(run.call_args_list[1].args[0][-1])
    assert run.call_args_list == [
        call(
            [
                *command,
                "scan",
                str(source_root),
                "--output-dir",
                str(scan_dir),
            ],
            check=False,
            capture_output=True,
            text=True,
        ),
        call(
            [
                *command,
                "export",
                str(scan_dir),
                "--export-format",
                "sarif",
                "--source-root",
                str(source_root),
                "--output",
                str(sarif_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        ),
    ]
    parse_sarif.assert_called_once_with(sarif_path, AnalysisTool.CODEX_SECURITY)
    assert not scan_dir.exists()


def test_run_codex_security_exports_incomplete_coverage_scan(tmp_path: Path):
    source_root = tmp_path / "source"
    workdir = tmp_path / "work"
    source_root.mkdir()

    scan_result = subprocess.CompletedProcess("scan", 2, "", "incomplete coverage")
    export_result = subprocess.CompletedProcess("export", 0, "", "")

    with patch(
        "secureforge.analyzers.codex_security._find_codex_security",
        return_value=["codex-security"],
    ), patch(
        "secureforge.analyzers.codex_security.subprocess.run",
        side_effect=[scan_result, export_result],
    ) as run, patch(
        "secureforge.analyzers.codex_security._parse_sarif",
        return_value=[],
    ):
        assert _run_codex_security_analysis(source_root, workdir) == []

    assert len(run.call_args_list) == 2
    assert run.call_args_list[0].kwargs["check"] is False
    assert run.call_args_list[1].kwargs["check"] is True


def test_evaluate_dispatches_to_codex_security(tmp_path: Path):
    evaluate.cache_clear()
    findings = [{"rule": "CWE-79", "analyzer": "codex-security"}]

    with patch(
        "secureforge.analyzers.evaluate._run_codex_security_analysis",
        return_value=findings,
    ) as run:
        result = evaluate(
            "print('hello')",
            str(tmp_path),
            AnalysisTool.CODEX_SECURITY,
        )

    assert result == findings
    run.assert_called_once()

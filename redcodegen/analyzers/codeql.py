import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any
from loguru import logger

from .common import _cleanup, _parse_sarif, AnalysisTool
from redcodegen.language import get_language_config, DEFAULT_LANGUAGE

def _find_codeql() -> str:
    """Find CodeQL binary in PATH.

    Returns:
        str: Path to codeql binary

    Raises:
        FileNotFoundError: If codeql is not found in PATH
    """
    codeql_path = shutil.which("codeql")
    if codeql_path is None:
        raise FileNotFoundError(
            "CodeQL not found in PATH. Please install CodeQL and ensure it's available in your PATH."
        )
    return codeql_path


def _write_cmake_build_files(source_root: Path) -> None:
    """Write a minimal CMakeLists.txt so CodeQL can trace a C/C++ build."""
    c_files = list(source_root.glob("*.c")) + list(source_root.glob("*.cpp"))
    if not c_files:
        return

    has_cpp = any(f.suffix == ".cpp" for f in c_files)
    languages = "C CXX" if has_cpp else "C"
    sources = " ".join(f.name for f in c_files)
    cmake_content = (
        "cmake_minimum_required(VERSION 3.10)\n"
        f"project(codeql_analysis {languages})\n"
        f"add_library(analysis_target OBJECT {sources})\n"
    )
    (source_root / "CMakeLists.txt").write_text(cmake_content, encoding="utf-8")


def _run_codeql_subprocess(cmd: list[str], step_name: str) -> subprocess.CompletedProcess:
    """Run a CodeQL subprocess, logging full output on failure."""
    try:
        return subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.debug(
            "CodeQL {} failed (rc={})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            step_name, exc.returncode,
            exc.stdout or "<empty>",
            exc.stderr or "<empty>",
        )
        raise


def _run_codeql_analysis(source_root: Path, workdir: Path, language: str = DEFAULT_LANGUAGE) -> List[Dict[str, Any]]:
    """Run CodeQL analysis for a source root and return parsed SARIF findings."""
    lang_config = get_language_config(language)
    codeql_bin = _find_codeql()
    workdir.mkdir(parents=True, exist_ok=True)

    db_dir = Path(tempfile.mkdtemp(prefix="codeql_db_", dir=workdir))
    sarif_file = tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.sarif',
        prefix='codeql_results_',
        dir=workdir,
        delete=False
    )
    sarif_path = Path(sarif_file.name)
    sarif_file.close()

    try:
        # C/C++ requires a traced build for CodeQL
        if lang_config.codeql_language == "cpp":
            _write_cmake_build_files(source_root)

        create_cmd = [
            codeql_bin,
            "database",
            "create",
            str(db_dir),
            f"--language={lang_config.codeql_language}",
            f"--source-root={source_root}",
            "--overwrite",
        ]
        if lang_config.codeql_language == "cpp":
            build_dir = source_root / "_build"
            build_script = source_root / "_codeql_build.sh"
            build_script.write_text(
                f"#!/bin/sh\ncmake -S {source_root} -B {build_dir} && cmake --build {build_dir}\n"
            )
            build_script.chmod(0o755)
            create_cmd.append(f"--command={build_script}")

        logger.debug(f"Creating CodeQL database in {db_dir} from {source_root}")
        _run_codeql_subprocess(create_cmd, "database create")

        logger.debug("Analyzing CodeQL database")
        _run_codeql_subprocess(
            [
                codeql_bin,
                "database",
                "analyze",
                str(db_dir),
                lang_config.codeql_queries,
                "--format=sarif-latest",
                f"--output={sarif_path}",
                "--download",
            ],
            "database analyze",
        )

        vulnerabilities = _parse_sarif(sarif_path, AnalysisTool.CODEQL)
        logger.debug(f"Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    finally:
        _cleanup(db_dir, sarif_path)

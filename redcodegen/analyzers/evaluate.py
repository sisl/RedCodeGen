
import subprocess
import tempfile
import shutil
import json
from pathlib import Path
from typing import List, Dict, Any
from functools import cache
from loguru import logger

from .common import _cleanup, _source_tree_mtime_ns, AnalysisTool
from .codeql import _run_codeql_analysis
from .semgrep import _run_semgrep_analysis
from redcodegen.language import get_language_config, DEFAULT_LANGUAGE

@cache
def evaluate(program: str, workdir: str = "/tmp", analysis_tool: AnalysisTool = AnalysisTool.SEMGREP, language: str = DEFAULT_LANGUAGE) -> List[Dict[str, Any]]:
    """Evaluates program via codeql in a temporary workdir

    Args:
        program (str): The source code to evaluate
        workdir (str, optional): The working directory to use. Defaults to "/tmp".
        analysis_tool (AnalysisTool, optional): The analysis tool to use. Defaults to AnalysisTool.SEMGREP.
        language (str, optional): Target programming language. Defaults to "python".

    Returns:
        List[Dict]: List of vulnerabilities found. Each dict contains:
            - cwe: CWE identifier (e.g., "CWE-89") or None
            - rule: CodeQL rule ID (e.g., "py/sql-injection")
            - line: Line number where vulnerability was found
            - message: Description of the vulnerability
            - analyzer: The analysis tool used (e.g., "codeql", "semgrep")

    Raises:
        FileNotFoundError: If CodeQL is not found in PATH
        subprocess.CalledProcessError: If CodeQL commands fail
    """
    lang_config = get_language_config(language)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    src_dir = Path(tempfile.mkdtemp(prefix="redcodegen_src_", dir=workdir))

    try:
        # Write program to source directory; use .cpp for C/C++ so the
        # compiler accepts both C and C++ code (LLMs often mix them).
        ext = ".cpp" if lang_config.codeql_language == "cpp" else lang_config.extension
        program_path = src_dir / f"program{ext}"
        program_path.write_text(program, encoding='utf-8')

        vulnerabilities = []

        if analysis_tool in (AnalysisTool.CODEQL, AnalysisTool.ALL):
            logger.debug("Evaluating with CodeQL")
            vulnerabilities.extend(_run_codeql_analysis(src_dir, workdir, language))

        if analysis_tool in (AnalysisTool.SEMGREP, AnalysisTool.ALL):
            logger.debug("Evaluating with Semgrep")
            vulnerabilities.extend(_run_semgrep_analysis(src_dir, workdir))

        return vulnerabilities

    finally:
        # Cleanup temporary source folder
        _cleanup(src_dir)


@cache
def _evaluate_codebase_cached(
    source_root: str,
    workdir: str,
    source_mtime_ns: int,
    analysis_tool: AnalysisTool = AnalysisTool.SEMGREP,
    language: str = DEFAULT_LANGUAGE,
) -> List[Dict[str, Any]]:
    # source_mtime_ns is included to invalidate cache when files change.
    del source_mtime_ns

    vulnerabilities = []

    if analysis_tool in (AnalysisTool.CODEQL, AnalysisTool.ALL):
        logger.debug("Evaluating codebase with CodeQL")
        vulnerabilities.extend(_run_codeql_analysis(Path(source_root), Path(workdir), language))

    if analysis_tool in (AnalysisTool.SEMGREP, AnalysisTool.ALL):
        logger.debug("Evaluating codebase with Semgrep")
        vulnerabilities.extend(_run_semgrep_analysis(Path(source_root), Path(workdir)))

    return vulnerabilities


def evaluate_codebase(path: str | Path, workdir: str | Path, analysis_tool: AnalysisTool = AnalysisTool.SEMGREP, language: str = DEFAULT_LANGUAGE) -> List[Dict[str, Any]]:
    """Evaluate a whole codebase (directory) via CodeQL.

    Args:
        path: Path to the source tree root.
        workdir: Working directory used for temporary CodeQL DB/SARIF files.
        analysis_tool: The analysis tool to use (e.g., "codeql", "semgrep", or "all").

    Returns:
        List[Dict]: Parsed vulnerabilities from SARIF.

    Raises:
        FileNotFoundError: If path does not exist or CodeQL is not in PATH.
        NotADirectoryError: If path is not a directory.
        subprocess.CalledProcessError: If CodeQL commands fail.
    """
    source_root = Path(path).expanduser().resolve()
    workdir_path = Path(workdir).expanduser().resolve()

    if not source_root.exists():
        raise FileNotFoundError(f"Codebase path does not exist: {source_root}")
    if not source_root.is_dir():
        raise NotADirectoryError(f"Codebase path must be a directory: {source_root}")

    source_mtime_ns = _source_tree_mtime_ns(source_root)
    return _evaluate_codebase_cached(str(source_root), str(workdir_path), source_mtime_ns, analysis_tool, language)


def evaluate_diff(path: str | Path, workdir: str | Path, analysis_tool: AnalysisTool = AnalysisTool.SEMGREP) -> List[Dict[str, Any]]:
    """Evaluate files changed in git diff by analyzing each changed file.

    This inspects `git diff --name-only` in `workdir`, then reads each changed
    file from `path` (falling back to `workdir` if needed), calls `evaluate(...)`
    on its full contents, and concatenates all vulnerability findings.

    Args:
        path: Root directory to resolve changed file paths from.
        workdir: Git working tree used to compute `git diff`.
        analysis_tool: The analysis tool to use (e.g., "codeql", "semgrep", or "all").

    Returns:
        List[Dict]: Concatenated vulnerability findings across all changed files.

    Raises:
        FileNotFoundError: If `path` or `workdir` does not exist.
        NotADirectoryError: If `path` or `workdir` is not a directory.
        subprocess.CalledProcessError: If git diff invocation fails.
    """
    source_root = Path(path).expanduser().resolve()
    workdir_path = Path(workdir).expanduser().resolve()

    if not source_root.exists():
        raise FileNotFoundError(f"Path does not exist: {source_root}")
    if not source_root.is_dir():
        raise NotADirectoryError(f"Path must be a directory: {source_root}")
    if not workdir_path.exists():
        raise FileNotFoundError(f"Workdir does not exist: {workdir_path}")
    if not workdir_path.is_dir():
        raise NotADirectoryError(f"Workdir must be a directory: {workdir_path}")

    diff_proc = subprocess.run(
        ["git", "-C", str(source_root), "diff", "--name-only"],
        check=True,
        capture_output=True,
        text=True,
    )
    changed_files = [line.strip() for line in diff_proc.stdout.splitlines() if line.strip()]

    findings: List[Dict[str, Any]] = []
    for rel_file in changed_files:
        rel_path = Path(rel_file)
        candidate = source_root / rel_path
        if not candidate.exists() or not candidate.is_file():
            logger.debug(f"Skipping changed path that is not a readable file: {rel_file}")
            continue

        try:
            program = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            logger.debug(f"Skipping non-text changed file: {candidate}")
            continue

        findings.extend(evaluate(program, str(workdir_path), analysis_tool))

    return findings

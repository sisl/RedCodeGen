"""
validator.py
Run CodeQL in a temporary folder order to evaluated generated code

Essentially dumps the input program into a temporary /tmp/randomsrcname/program.py, then run

>>> codeql database create /tmp/randomdbname --language=python --source-root=/tmp/randomsrcname --overwrite
>>> codeql database analyze /tmp/randomdbname codeql/python-queries --format=sarifv2.1.0 --output=tmp/randomresults.sarif --download

Then interpreters the sarif in a reasonable way before returning results. Should fail gracefully whenever codeql cannot be found.
"""

import subprocess
import tempfile
import shutil
import json
from pathlib import Path
from typing import List, Dict, Any
from functools import cache
from loguru import logger

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


def _parse_sarif(sarif_path: Path) -> List[Dict[str, Any]]:
    """Parse SARIF output file and extract vulnerability information.

    Args:
        sarif_path: Path to the SARIF output file

    Returns:
        List of dicts with keys: cwe, rule, line, message
    """
    with open(sarif_path, 'r', encoding='utf-8') as f:
        sarif = json.load(f)

    vulnerabilities = []

    # SARIF structure: runs[0].results[] contains the findings
    if 'runs' not in sarif or len(sarif['runs']) == 0:
        return vulnerabilities

    run = sarif['runs'][0]
    results = run.get('results', [])

    for result in results:
        vuln = {}

        # Extract rule ID (e.g., "py/sql-injection")
        vuln['rule'] = result.get('ruleId', 'unknown')

        # Extract message
        message = result.get('message', {})
        vuln['message'] = message.get('text', '')

        # Extract line number from first location
        locations = result.get('locations', [])
        if locations:
            physical_location = locations[0].get('physicalLocation', {})
            region = physical_location.get('region', {})
            vuln['line'] = region.get('startLine', 0)
        else:
            vuln['line'] = 0

        # Extract CWE from rule metadata (rules are in run.tool.driver.rules)
        vuln['cwe'] = None
        rule_id = result.get('ruleId')
        if rule_id:
            rules = run.get('tool', {}).get('driver', {}).get('rules', [])
            for rule in rules:
                if rule.get('id') == rule_id:
                    # Look for CWE in tags or properties
                    tags = rule.get('properties', {}).get('tags', [])
                    for tag in tags:
                        if tag.startswith('CWE-'):
                            vuln['cwe'] = tag
                            break
                    # Also check in security-severity metadata
                    if not vuln['cwe']:
                        security_metadata = rule.get('properties', {}).get('security-severity')
                        if security_metadata:
                            # Try to extract CWE from rule ID (e.g., py/sql-injection -> CWE-89)
                            # This is heuristic-based
                            pass
                    break

        del vuln["cwe"]
        vulnerabilities.append(vuln)

    return vulnerabilities


def _cleanup(*paths: Path):
    """Safely cleanup temporary directories and files.

    Args:
        *paths: Paths to remove
    """
    for path in paths:
        if path and path.exists():
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            except Exception as e:
                logger.warning(f"Failed to cleanup {path}: {e}")


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


def _write_cmake_build_files(source_root: Path) -> None:
    """Write a minimal CMakeLists.txt so CodeQL can trace a C/C++ build."""
    c_files = list(source_root.glob("*.c")) + list(source_root.glob("*.cpp"))
    if not c_files:
        return

    sources = " ".join(f.name for f in c_files)
    cmake_content = (
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(codeql_analysis C)\n"
        f"add_library(analysis_target OBJECT {sources})\n"
    )
    (source_root / "CMakeLists.txt").write_text(cmake_content, encoding="utf-8")


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
            create_cmd.append(
                f"--command=cmake -S {source_root} -B {build_dir} && cmake --build {build_dir}"
            )

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

        vulnerabilities = _parse_sarif(sarif_path)
        logger.debug(f"Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    finally:
        _cleanup(db_dir, sarif_path)


def _source_tree_mtime_ns(source_root: Path) -> int:
    """Return a coarse fingerprint of a codebase based on latest file mtime."""
    latest_mtime = source_root.stat().st_mtime_ns
    for p in source_root.rglob("*"):
        try:
            if p.is_file():
                latest_mtime = max(latest_mtime, p.stat().st_mtime_ns)
        except FileNotFoundError:
            # Ignore races if files are moved/deleted during traversal.
            continue
    return latest_mtime


@cache
def evaluate(program: str, workdir: str = "/tmp", language: str = DEFAULT_LANGUAGE) -> List[Dict[str, Any]]:
    """Evaluates program via codeql in a temporary workdir

    Args:
        program (str): The source code to evaluate
        workdir (str, optional): The working directory to use. Defaults to "/tmp".
        language (str, optional): Target programming language. Defaults to "python".

    Returns:
        List[Dict]: List of vulnerabilities found. Each dict contains:
            - cwe: CWE identifier (e.g., "CWE-89") or None
            - rule: CodeQL rule ID (e.g., "py/sql-injection")
            - line: Line number where vulnerability was found
            - message: Description of the vulnerability

    Raises:
        FileNotFoundError: If CodeQL is not found in PATH
        subprocess.CalledProcessError: If CodeQL commands fail
    """
    lang_config = get_language_config(language)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    src_dir = Path(tempfile.mkdtemp(prefix="codeql_src_", dir=workdir))

    try:
        # Write program to source directory
        program_path = src_dir / f"program{lang_config.extension}"
        program_path.write_text(program, encoding='utf-8')

        return _run_codeql_analysis(src_dir, workdir, language)

    finally:
        # Cleanup temporary source folder
        _cleanup(src_dir)


@cache
def _evaluate_codebase_cached(
    source_root: str,
    workdir: str,
    source_mtime_ns: int
) -> List[Dict[str, Any]]:
    # source_mtime_ns is included to invalidate cache when files change.
    del source_mtime_ns
    return _run_codeql_analysis(Path(source_root), Path(workdir))


def evaluate_codebase(path: str | Path, workdir: str | Path) -> List[Dict[str, Any]]:
    """Evaluate a whole codebase (directory) via CodeQL.

    Args:
        path: Path to the source tree root.
        workdir: Working directory used for temporary CodeQL DB/SARIF files.

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
    return _evaluate_codebase_cached(str(source_root), str(workdir_path), source_mtime_ns)


def evaluate_diff(path: str | Path, workdir: str | Path) -> List[Dict[str, Any]]:
    """Evaluate files changed in git diff by analyzing each changed file.

    This inspects `git diff --name-only` in `workdir`, then reads each changed
    file from `path` (falling back to `workdir` if needed), calls `evaluate(...)`
    on its full contents, and concatenates all vulnerability findings.

    Args:
        path: Root directory to resolve changed file paths from.
        workdir: Git working tree used to compute `git diff`.

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

        findings.extend(evaluate(program, str(workdir_path)))

    return findings

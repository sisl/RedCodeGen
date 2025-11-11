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
import logging
from pathlib import Path
from typing import List, Dict
from functools import cache

logger = logging.getLogger("redcodegen")


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


def _parse_sarif(sarif_path: Path) -> List[Dict[str, any]]:
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

@cache
def evaluate(program: str, workdir: str = "/tmp") -> List[Dict[str, any]]:
    """Evaluates program via codeql in a temporary workdir

    Args:
        program (str): The source code to evaluate
        workdir (str, optional): The working directory to use. Defaults to "/tmp".

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
    workdir = Path(workdir)

    # Find CodeQL binary (raises if not found)
    codeql_bin = _find_codeql()

    # Create temporary directories
    src_dir = Path(tempfile.mkdtemp(prefix="codeql_src_", dir=workdir))
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
        # Write program to source directory
        program_path = src_dir / "program.py"
        program_path.write_text(program, encoding='utf-8')

        # Create CodeQL database
        logger.debug(f"Creating CodeQL database in {db_dir}")
        subprocess.run(
            [
                codeql_bin,
                "database",
                "create",
                str(db_dir),
                "--language=python",
                f"--source-root={src_dir}",
                "--overwrite"
            ],
            check=True,
            capture_output=True,
            text=True
        )

        # Analyze database
        logger.debug(f"Analyzing CodeQL database")
        subprocess.run(
            [
                codeql_bin,
                "database",
                "analyze",
                str(db_dir),
                "codeql/python-queries",
                "--format=sarif-latest",
                f"--output={sarif_path}",
                "--download"
            ],
            check=True,
            capture_output=True,
            text=True
        )

        # Parse SARIF results
        vulnerabilities = _parse_sarif(sarif_path)
        logger.debug(f"Found {len(vulnerabilities)} vulnerabilities")

        return vulnerabilities

    finally:
        # Cleanup temporary files
        _cleanup(src_dir, db_dir, sarif_path)




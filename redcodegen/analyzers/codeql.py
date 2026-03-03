import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any
from loguru import logger

from .common import _cleanup, _parse_sarif, AnalysisTool

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

def _run_codeql_analysis(source_root: Path, workdir: Path) -> List[Dict[str, Any]]:
    """Run CodeQL analysis for a source root and return parsed SARIF findings."""
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
        logger.debug(f"Creating CodeQL database in {db_dir} from {source_root}")
        subprocess.run(
            [
                codeql_bin,
                "database",
                "create",
                str(db_dir),
                "--language=python",
                f"--source-root={source_root}",
                "--overwrite"
            ],
            check=True,
            capture_output=True,
            text=True
        )

        logger.debug("Analyzing CodeQL database")
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

        vulnerabilities = _parse_sarif(sarif_path, AnalysisTool.CODEQL)
        logger.debug(f"Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    finally:
        _cleanup(db_dir, sarif_path)

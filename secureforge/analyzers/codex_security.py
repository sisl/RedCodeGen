import shutil
import subprocess
import tempfile
from functools import cache
from pathlib import Path
from typing import Any, Dict, List

from loguru import logger

from .common import AnalysisTool, _cleanup, _parse_sarif


@cache
def _find_codex_security() -> list[str]:
    """Return the command prefix for an installed Codex Security CLI."""
    codex_security_path = shutil.which("codex-security")
    if codex_security_path:
        return [codex_security_path]

    npx_path = shutil.which("npx")
    if npx_path:
        # Avoid downloading analyzer code implicitly. `npm install
        # @openai/codex-security` makes it available to this npx invocation.
        command = [npx_path, "--no-install", "@openai/codex-security"]
        try:
            subprocess.run(
                [*command, "--version"],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError:
            pass
        else:
            return command

    raise FileNotFoundError(
        "Codex Security CLI not found; install it with "
        "`npm install @openai/codex-security`"
    )


def _run_codex_security_analysis(
    source_root: Path, workdir: Path
) -> List[Dict[str, Any]]:
    """Run Codex Security and return findings parsed from its SARIF export."""
    command = _find_codex_security()
    workdir.mkdir(parents=True, exist_ok=True)

    scan_dir = Path(tempfile.mkdtemp(prefix="codex_security_scan_", dir=workdir))
    sarif_path = scan_dir.parent / f"{scan_dir.name}.sarif"

    try:
        logger.debug(f"Running Codex Security analysis on {source_root}")
        scan_result = subprocess.run(
            [
                *command,
                "scan",
                str(source_root),
                "--output-dir",
                str(scan_dir),
            ],
            # Exit 2 can mean that the scan completed with incomplete
            # coverage. Such scans still contain an exportable result bundle,
            # so let `export` below decide whether the bundle is valid.
            check=False,
            capture_output=True,
            text=True,
        )
        if scan_result.returncode != 0:
            logger.warning(
                "Codex Security scan exited with status {}; attempting to "
                "export its completed result bundle",
                scan_result.returncode,
            )

        subprocess.run(
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
        )

        vulnerabilities = _parse_sarif(sarif_path, AnalysisTool.CODEX_SECURITY)
        logger.debug(f"Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    finally:
        # Scan bundles may contain source excerpts and vulnerability details.
        _cleanup(scan_dir, sarif_path)

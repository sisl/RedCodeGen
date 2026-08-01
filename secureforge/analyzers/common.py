import shutil
import json
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any
from loguru import logger

class AnalysisTool(Enum):
    CODEQL = "codeql"
    CODEX_SECURITY = "codex-security"
    SEMGREP = "semgrep"
    ALL = "all"


# SARIF defaultConfiguration.level → representative CVSS-range numeric severity.
# Used as fallback when properties.security-severity (CodeQL) is absent (Semgrep).
_SARIF_LEVEL_SEVERITY: dict[str, float] = {
    "error": 8.0,    # High (CVSS 7.0–8.9)
    "warning": 5.0,  # Medium (CVSS 4.0–6.9)
    "note": 2.0,     # Low (CVSS 0.1–3.9)
}

def _parse_sarif(sarif_path: Path, analysis_tool: AnalysisTool) -> List[Dict[str, Any]]:
    """Parse SARIF output file and extract vulnerability information.

    Args:
        sarif_path: Path to the SARIF output file
        analysis_tool: The analysis tool used (e.g., "codeql", "semgrep")

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
                    severity_raw = rule.get('properties', {}).get('security-severity')
                    if severity_raw is not None:
                        vuln['security_severity'] = float(severity_raw)
                    else:
                        level = rule.get('defaultConfiguration', {}).get('level')
                        vuln['security_severity'] = _SARIF_LEVEL_SEVERITY.get(level)
                    break
            else:
                vuln['security_severity'] = None
        else:
            vuln['security_severity'] = None

        del vuln["cwe"]
        vuln["analyzer"] = analysis_tool.value # Set the analyzer
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

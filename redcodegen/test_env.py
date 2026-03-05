"""Dependency extraction and uv environment creation for test isolation."""

import re
import shutil
import subprocess
import sys
from pathlib import Path

from loguru import logger

# Regex for top-level imports: `import X` and `from X import ...`
_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)

# Import-name -> PyPI-package-name mismatches, scoped to CODEQL_LIBRARIES
_IMPORT_TO_PYPI: dict[str, str] = {
    "Crypto": "pycryptodome",        # Cryptodome
    "MySQLdb": "mysqlclient",        # MySQLdb
    "bson": "pymongo",               # BSon
    "cassandra": "cassandra-driver",  # CassandraDriver
    "ldap": "python-ldap",           # Ldap
    "rest_framework": "djangorestframework",  # RestFramework
    "ruamel": "ruamel.yaml",         # RuamelYaml
    "yaml": "pyyaml",               # Yaml
}

# Modules that are internal to our test harness — never install these
_INTERNAL_MODULES = frozenset({"solution", "test_solution", "conftest"})


def extract_imports(*sources: str) -> set[str]:
    """Extract top-level module names from Python source strings."""
    modules: set[str] = set()
    for src in sources:
        for match in _IMPORT_RE.finditer(src):
            modules.add(match.group(1))
    return modules


def resolve_packages(modules: set[str]) -> list[str]:
    """Filter stdlib/internal modules and map to PyPI package names."""
    packages: list[str] = []
    stdlib = sys.stdlib_module_names
    for mod in sorted(modules):
        if mod in stdlib or mod in _INTERNAL_MODULES:
            continue
        packages.append(_IMPORT_TO_PYPI.get(mod, mod))
    return packages


def create_uv_env(
    workdir: Path,
    packages: list[str],
    timeout: int = 120,
) -> Path | None:
    """Create a uv venv and install packages + pytest. Returns python path or None."""
    if not shutil.which("uv"):
        logger.debug("uv not found on PATH, skipping venv creation")
        return None

    venv_dir = workdir / ".venv"
    python_path = venv_dir / "bin" / "python"

    try:
        subprocess.run(
            ["uv", "venv", str(venv_dir), "--python", sys.executable],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )

        all_packages = ["pytest"] + packages
        subprocess.run(
            ["uv", "pip", "install", "--python", str(python_path)] + all_packages,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )

        return python_path
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        logger.warning(f"Failed to create uv environment: {e}")
        return None

"""Dependency extraction and uv environment creation for test isolation."""

import re
import shutil
import subprocess
import sys
import threading
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

# Packages that need extras for testing (e.g. fastapi[standard] includes httpx)
_PACKAGE_EXTRAS: dict[str, str] = {
    "fastapi": "fastapi[standard]",
    "starlette": "starlette[full]",
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
    """Filter stdlib/internal modules and map to PyPI package names with extras."""
    packages: list[str] = []
    stdlib = sys.stdlib_module_names
    for mod in sorted(modules):
        if mod in stdlib or mod in _INTERNAL_MODULES:
            continue
        pkg = _IMPORT_TO_PYPI.get(mod, mod)
        pkg = _PACKAGE_EXTRAS.get(pkg, pkg)
        packages.append(pkg)
    return packages


def build_script_header(code: str, test_code: str) -> str:
    """Build a PEP 723 inline script metadata block for dependencies."""
    modules = extract_imports(code, test_code)
    packages = resolve_packages(modules)
    packages = sorted(set(packages + ["pytest"]))
    lines = [
        "# /// script",
        '# requires-python = ">=3.11"',
        "# dependencies = [",
    ]
    for pkg in packages:
        lines.append(f'#   "{pkg}",')
    lines += ["# ]", "# ///", ""]
    return "\n".join(lines)


def build_script_footer() -> str:
    """Build a __main__ block that invokes pytest on the script itself."""
    return (
        '\n\nif __name__ == "__main__":\n'
        "    import sys\n"
        "    sys.exit(pytest.main([__file__, \"-v\"]))\n"
    )


_uv_python_installed = False
_uv_python_lock = threading.Lock()


def ensure_uv_python():
    """Install Python 3.12 via uv once (thread-safe). Call before parallel work."""
    global _uv_python_installed
    if _uv_python_installed:
        return
    with _uv_python_lock:
        if _uv_python_installed:
            return
        subprocess.run(
            ["uv", "python", "install", "3.12"],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        _uv_python_installed = True


def create_uv_env(
    workdir: Path,
    packages: list[str],
    timeout: int = 120,
) -> bool:
    """Create a uv project and add packages + pytest. Returns True on success."""
    if not shutil.which("uv"):
        logger.debug("uv not found on PATH, skipping env creation")
        return False

    try:
        ensure_uv_python()
        subprocess.run(
            ["uv", "init", "--no-readme", "--python", "3.12"],
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )

        all_packages = ["pytest"] + packages
        subprocess.run(
            ["uv", "add"] + all_packages,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )

        return True
    except subprocess.CalledProcessError as e:
        logger.warning(
            f"Failed to create uv environment: {e}\n"
            f"  stdout: {e.stdout}\n"
            f"  stderr: {e.stderr}"
        )
        return False
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning(f"Failed to create uv environment: {e}")
        return False

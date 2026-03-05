"""Tests for build_script_header (PEP 723 inline metadata)."""

from redcodegen.test_env import build_script_footer, build_script_header


class TestBuildScriptHeader:
    def test_includes_pytest(self):
        header = build_script_header("x = 1", "assert x == 1")
        assert "pytest" in header

    def test_pep723_structure(self):
        header = build_script_header("import flask", "import pytest")
        lines = header.strip().splitlines()
        assert lines[0] == "# /// script"
        assert lines[-1] == "# ///"
        assert '# requires-python = ">=3.11"' in header

    def test_includes_third_party_deps(self):
        header = build_script_header(
            "from flask import Flask", "from fastapi import FastAPI"
        )
        assert '"flask"' in header
        assert '"fastapi[standard]"' in header
        assert '"pytest"' in header

    def test_no_stdlib_deps(self):
        header = build_script_header("import os\nimport json", "import sys")
        # Should only have pytest, no stdlib
        assert '"os"' not in header
        assert '"json"' not in header
        assert '"sys"' not in header
        assert '"pytest"' in header

    def test_deduplicates_pytest(self):
        """pytest shouldn't appear twice even if test code imports it."""
        header = build_script_header("x = 1", "import pytest")
        count = header.count('"pytest"')
        assert count == 1

    def test_sorted_dependencies(self):
        header = build_script_header(
            "import requests\nimport flask", "import pytest"
        )
        lines = [l for l in header.splitlines() if l.startswith('#   "')]
        pkg_names = [l.strip().strip("#").strip().strip('",') for l in lines]
        assert pkg_names == sorted(pkg_names)

    def test_maps_pypi_names(self):
        header = build_script_header("import yaml", "import pytest")
        assert '"pyyaml"' in header
        assert '"yaml"' not in header

    def test_ends_with_newline(self):
        header = build_script_header("x = 1", "assert x")
        assert header.endswith("\n")


class TestBuildScriptFooter:
    def test_contains_main_guard(self):
        footer = build_script_footer()
        assert '__name__ == "__main__"' in footer

    def test_contains_pytest_main(self):
        footer = build_script_footer()
        assert "pytest.main" in footer

    def test_contains_sys_exit(self):
        footer = build_script_footer()
        assert "sys.exit" in footer

"""Tests for dependency extraction and resolution."""

import pytest

from redcodegen.test_env import extract_imports, resolve_packages


class TestExtractImports:
    def test_import_statement(self):
        src = "import flask\nimport os"
        assert extract_imports(src) == {"flask", "os"}

    def test_from_import(self):
        src = "from flask import Flask\nfrom pathlib import Path"
        assert extract_imports(src) == {"flask", "pathlib"}

    def test_multiple_sources(self):
        result = extract_imports("import flask", "import requests")
        assert result == {"flask", "requests"}

    def test_indented_import(self):
        src = "    import json"
        assert extract_imports(src) == {"json"}

    def test_empty_source(self):
        assert extract_imports("") == set()

    def test_no_imports(self):
        assert extract_imports("x = 1\nprint(x)") == set()

    def test_comment_not_matched(self):
        # The regex matches lines starting with optional whitespace + import
        # A comment like "# import foo" won't match because # isn't whitespace
        src = "# import fake\nimport real"
        assert extract_imports(src) == {"real"}


class TestResolvePackages:
    def test_filters_stdlib(self):
        mods = {"os", "sys", "json", "flask"}
        pkgs = resolve_packages(mods)
        assert pkgs == ["flask"]

    def test_filters_internal(self):
        mods = {"solution", "test_solution", "flask"}
        pkgs = resolve_packages(mods)
        assert pkgs == ["flask"]

    def test_maps_pypi_names(self):
        mods = {"yaml", "Crypto", "bson"}
        pkgs = resolve_packages(mods)
        assert "pyyaml" in pkgs
        assert "pycryptodome" in pkgs
        assert "pymongo" in pkgs

    def test_passthrough_unknown(self):
        mods = {"requests"}
        pkgs = resolve_packages(mods)
        assert pkgs == ["requests"]

    def test_applies_package_extras(self):
        mods = {"fastapi"}
        pkgs = resolve_packages(mods)
        assert pkgs == ["fastapi[standard]"]

    def test_applies_starlette_extras(self):
        mods = {"starlette"}
        pkgs = resolve_packages(mods)
        assert pkgs == ["starlette[full]"]

    def test_empty(self):
        assert resolve_packages(set()) == []

    def test_sorted_output(self):
        mods = {"requests", "flask", "click"}
        pkgs = resolve_packages(mods)
        assert pkgs == sorted(pkgs)

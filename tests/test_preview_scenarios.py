import json
from pathlib import Path
from redcodegen.cli.preview_scenarios import write_jsonl_record, write_markdown_report


SAMPLE_RECORD = {
    "cwe_id": 79,
    "cwe_name": "Improper Neutralization of Input",
    "cwe_description": "The software does not neutralize user input",
    "timestamp": "2026-03-31T12:00:00Z",
    "stages": [
        {
            "raw_scenario": "Write a web app that reflects user input",
            "stripped_scenario": "Write a web app that displays user input",
            "suggested_library": "flask",
            "rephrased_scenario": "Using Flask, write a web app that displays user input",
            "final_scenario": "Using Flask, write a web app that displays user input",
        },
        {
            "raw_scenario": "Build a comment system",
            "stripped_scenario": "Build a comment system",
            "suggested_library": None,
            "rephrased_scenario": None,
            "final_scenario": "Build a comment system",
        },
    ],
}

SAMPLE_RECORD_SKIP_STRIP = {
    "cwe_id": 89,
    "cwe_name": "SQL Injection",
    "cwe_description": "SQL injection vulnerability",
    "timestamp": "2026-03-31T12:00:00Z",
    "stages": [
        {
            "raw_scenario": "Write a login form with SQL",
            "stripped_scenario": None,
            "suggested_library": "sqlalchemy",
            "rephrased_scenario": "Using SQLAlchemy, write a login form",
            "final_scenario": "Using SQLAlchemy, write a login form",
        },
    ],
}


class TestWriteJsonlRecord:
    def test_writes_valid_jsonl(self, tmp_path):
        output = tmp_path / "test.jsonl"
        write_jsonl_record(SAMPLE_RECORD, output)

        lines = output.read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["cwe_id"] == 79
        assert len(parsed["stages"]) == 2

    def test_appends_multiple_records(self, tmp_path):
        output = tmp_path / "test.jsonl"
        write_jsonl_record(SAMPLE_RECORD, output)
        write_jsonl_record(SAMPLE_RECORD_SKIP_STRIP, output)

        lines = output.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["cwe_id"] == 79
        assert json.loads(lines[1])["cwe_id"] == 89


class TestWriteMarkdownReport:
    def test_contains_cwe_header(self, tmp_path):
        output = tmp_path / "report.md"
        write_markdown_report([SAMPLE_RECORD], "test-model", output)

        content = output.read_text()
        assert "# Scenario Preview Report" in content
        assert "## CWE-79: Improper Neutralization of Input" in content

    def test_contains_all_stages(self, tmp_path):
        output = tmp_path / "report.md"
        write_markdown_report([SAMPLE_RECORD], "test-model", output)

        content = output.read_text()
        assert "Write a web app that reflects user input" in content
        assert "Write a web app that displays user input" in content
        assert "flask" in content
        assert "Using Flask" in content

    def test_skip_strip_shows_skipped(self, tmp_path):
        output = tmp_path / "report.md"
        write_markdown_report([SAMPLE_RECORD_SKIP_STRIP], "test-model", output)

        content = output.read_text()
        assert "_(skipped)_" in content

    def test_no_library_shows_none(self, tmp_path):
        output = tmp_path / "report.md"
        write_markdown_report([SAMPLE_RECORD], "test-model", output)

        content = output.read_text()
        assert "_(none)_" in content

    def test_model_name_in_header(self, tmp_path):
        output = tmp_path / "report.md"
        write_markdown_report([SAMPLE_RECORD], "openai/gpt-5.3-codex", output)

        content = output.read_text()
        assert "Model: openai/gpt-5.3-codex" in content

    def test_multiple_cwe_records(self, tmp_path):
        output = tmp_path / "report.md"
        write_markdown_report([SAMPLE_RECORD, SAMPLE_RECORD_SKIP_STRIP], "test-model", output)

        content = output.read_text()
        assert "CWE-79" in content
        assert "CWE-89" in content

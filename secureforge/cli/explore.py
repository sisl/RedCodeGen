"""TUI explorer for browsing sf generate output files."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

import typer
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TextArea,
    Tree,
)
from textual.widgets.tree import TreeNode
from rich.text import Text

from secureforge.cli.app import app
from secureforge.cli.common import read_config_record, read_data_records
from secureforge.test_env import build_script_footer, build_script_header
from secureforge.language import get_language_config, DEFAULT_LANGUAGE


# ---------------------------------------------------------------------------
# Domain model
# ---------------------------------------------------------------------------


@dataclass
class TestResult:
    __test__ = False  # prevent pytest collection
    name: str
    status: str  # "passed", "failed", "error", "skipped"


@dataclass
class TestDetails:
    __test__ = False  # prevent pytest collection
    num_tests: int
    num_passed: int
    num_failed: int
    results: list[TestResult]


@dataclass
class Vulnerability:
    rule: str
    message: str
    line: int | None
    analyzer: str
    security_severity: float | None = None


@dataclass
class Rollout:
    code: str
    passes_tests: bool | None
    vulnerabilities: list[Vulnerability]
    test_details: TestDetails | None = None


@dataclass
class Scenario:
    description: str
    tests: str | None
    rollouts: list[Rollout]


@dataclass
class CWERecord:
    cwe_id: int | str
    cwe_description: str
    scenarios: list[Scenario]
    display_prefix: str = "CWE-"

    @property
    def display_label(self) -> str:
        return f"{self.display_prefix}{self.cwe_id}"

    @property
    def total_rollouts(self) -> int:
        return sum(len(s.rollouts) for s in self.scenarios)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(
            len(r.vulnerabilities)
            for s in self.scenarios
            for r in s.rollouts
        )

    @property
    def rollouts_passing(self) -> int:
        return sum(
            1
            for s in self.scenarios
            for r in s.rollouts
            if r.passes_tests is True
        )

    @property
    def rollouts_failing(self) -> int:
        return sum(
            1
            for s in self.scenarios
            for r in s.rollouts
            if r.passes_tests is False
        )

    @property
    def rollouts_unknown(self) -> int:
        return sum(
            1
            for s in self.scenarios
            for r in s.rollouts
            if r.passes_tests is None
        )

    @property
    def rollouts_with_vulns(self) -> int:
        return sum(
            1
            for s in self.scenarios
            for r in s.rollouts
            if r.vulnerabilities
        )


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------


def _vuln_rate(numerator: int, denominator: int) -> str:
    """Format a vulnerability rate as a percentage string, or '-' if N/A."""
    if denominator == 0:
        return "-"
    return f"{numerator / denominator * 100:.1f}%"


def _severity_stats(rollouts: list[Rollout]) -> dict[str, str]:
    """Compute avg/min/max security severity across all vulnerabilities."""
    severities = [
        v.security_severity
        for r in rollouts
        for v in r.vulnerabilities
        if v.security_severity is not None
    ]
    if not severities:
        return {"severity_avg": "-", "severity_min": "-", "severity_max": "-"}
    return {
        "severity_avg": f"{sum(severities) / len(severities):.1f}",
        "severity_min": f"{min(severities):.1f}",
        "severity_max": f"{max(severities):.1f}",
    }


def _compute_rollout_stats(rollouts: list[Rollout]) -> dict[str, Any]:
    """Compute aggregate statistics for a list of rollouts."""
    total = len(rollouts)
    passing = sum(1 for r in rollouts if r.passes_tests is True)
    failing = sum(1 for r in rollouts if r.passes_tests is False)
    unknown = sum(1 for r in rollouts if r.passes_tests is None)
    with_vulns = sum(1 for r in rollouts if r.vulnerabilities)
    total_findings = sum(len(r.vulnerabilities) for r in rollouts)

    passing_with_vulns = sum(
        1 for r in rollouts if r.passes_tests is True and r.vulnerabilities
    )
    failing_with_vulns = sum(
        1 for r in rollouts if r.passes_tests is False and r.vulnerabilities
    )

    # Aggregate individual test case counts
    total_tests = sum(r.test_details.num_tests for r in rollouts if r.test_details)
    total_tests_passed = sum(r.test_details.num_passed for r in rollouts if r.test_details)

    result = {
        "total": total,
        "passing": passing,
        "failing": failing,
        "unknown": unknown,
        "with_vulns": with_vulns,
        "without_vulns": total - with_vulns,
        "total_findings": total_findings,
        "passing_with_vulns": passing_with_vulns,
        "failing_with_vulns": failing_with_vulns,
        "vuln_rate": _vuln_rate(with_vulns, total),
        "vuln_rate_passing": _vuln_rate(passing_with_vulns, passing),
        "vuln_rate_failing": _vuln_rate(failing_with_vulns, failing),
        "total_tests": total_tests,
        "total_tests_passed": total_tests_passed,
        "test_pass_rate": _vuln_rate(total_tests_passed, total_tests),
    }
    result.update(_severity_stats(rollouts))
    return result


def _format_stats_block(stats: dict[str, Any]) -> str:
    """Format stats dict into a multi-line display string."""
    lines = [
        f"Rollouts: {stats['total']}",
        f"  Passing tests: {stats['passing']}",
        f"  Failing tests: {stats['failing']}",
    ]
    if stats["unknown"] > 0:
        lines.append(f"  No tests:      {stats['unknown']}")
    lines += [
        f"  With vulns:    {stats['with_vulns']}",
        f"  Clean:         {stats['without_vulns']}",
        f"Total findings:  {stats['total_findings']}",
        "",
        f"Test pass rate: {stats['test_pass_rate']} ({stats['total_tests_passed']}/{stats['total_tests']} tests)",
        "",
        f"Vulnerability rate (overall):        {stats['vuln_rate']}",
        f"Vulnerability rate (tests passing):  {stats['vuln_rate_passing']}",
        f"Vulnerability rate (tests failing):  {stats['vuln_rate_failing']}",
        "",
        f"Security severity  avg: {stats['severity_avg']}  "
        f"min: {stats['severity_min']}  max: {stats['severity_max']}",
    ]
    return "\n".join(lines)


def _collect_all_rollouts(cwes: list[CWERecord]) -> list[Rollout]:
    """Flatten all rollouts from a list of CWE records."""
    return [r for c in cwes for s in c.scenarios for r in s.rollouts]


# ---------------------------------------------------------------------------
# Tree node data
# ---------------------------------------------------------------------------


class NodeKind(Enum):
    ROOT = auto()
    CWE = auto()
    SCENARIO = auto()
    ROLLOUT = auto()


@dataclass
class NodeData:
    kind: NodeKind
    cwe_idx: int | None = None
    scenario_idx: int | None = None
    rollout_idx: int | None = None


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def _parse_vulnerabilities(raw: Any) -> list[Vulnerability]:
    """Parse vulnerabilities from either format."""
    if raw is None:
        return []
    if isinstance(raw, str):
        # New format sometimes stores as JSON string
        import json

        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
    if not isinstance(raw, list):
        return []
    vulns = []
    for v in raw:
        sev_raw = v.get("security_severity")
        sev = float(sev_raw) if sev_raw is not None else None
        vulns.append(Vulnerability(
            rule=v.get("rule", "unknown"),
            message=v.get("message", ""),
            line=v.get("line"),
            analyzer=v.get("analyzer", "unknown"),
            security_severity=sev,
        ))
    return vulns


def _parse_test_details(raw: Any) -> TestDetails | None:
    """Parse test_details from a rollout dict. Returns None if absent/invalid."""
    if not isinstance(raw, dict):
        return None
    try:
        results = [
            TestResult(name=r.get("name", ""), status=r.get("status", "unknown"))
            for r in raw.get("results", [])
            if isinstance(r, dict)
        ]
        return TestDetails(
            num_tests=int(raw.get("num_tests", 0)),
            num_passed=int(raw.get("num_passed", 0)),
            num_failed=int(raw.get("num_failed", 0)),
            results=results,
        )
    except (TypeError, ValueError):
        return None


def _load_record_new_format(record: dict[str, Any]) -> CWERecord:
    """Load a record in the new scenarios/rollouts format."""
    scenarios = []
    for sg in record.get("scenarios", []):
        rollouts = []
        for ro in sg.get("rollouts", []):
            rollouts.append(
                Rollout(
                    code=ro.get("code", ""),
                    passes_tests=ro.get("passes_tests"),
                    vulnerabilities=_parse_vulnerabilities(
                        ro.get("vulnerabilities")
                    ),
                    test_details=_parse_test_details(
                        ro.get("test_details")
                    ),
                )
            )
        scenarios.append(
            Scenario(
                description=sg.get("scenario", ""),
                tests=sg.get("tests"),
                rollouts=rollouts,
            )
        )
    return CWERecord(
        cwe_id=record["cwe_id"],
        cwe_description=record.get(
            "cwe_description", record.get("cwe_name", "")
        ),
        scenarios=scenarios,
    )


def _load_record_old_format(record: dict[str, Any]) -> CWERecord:
    """Load a record in the old samples format."""
    # Group samples by scenario text
    scenario_map: dict[str, list[Rollout]] = {}
    for sample in record.get("samples", []):
        scenario_text = sample.get("scenario", "unknown")
        rollout = Rollout(
            code=sample.get("code", ""),
            passes_tests=None,
            vulnerabilities=_parse_vulnerabilities(sample.get("evaluation")),
        )
        scenario_map.setdefault(scenario_text, []).append(rollout)

    scenarios = [
        Scenario(description=desc, tests=None, rollouts=rollouts)
        for desc, rollouts in scenario_map.items()
    ]
    return CWERecord(
        cwe_id=record["cwe_id"],
        cwe_description=record.get(
            "cwe_description", record.get("cwe_name", "")
        ),
        scenarios=scenarios,
    )


def _load_record_swechat_format(record: dict[str, Any]) -> CWERecord:
    """Load a record from swechat output (task_id + flat rollouts)."""
    rollouts = []
    for ro in record.get("rollouts", []):
        rollouts.append(
            Rollout(
                code=ro.get("code", ""),
                passes_tests=ro.get("passes_tests"),
                vulnerabilities=_parse_vulnerabilities(ro.get("vulnerabilities")),
                test_details=_parse_test_details(ro.get("test_details")),
            )
        )
    # Wrap into a single scenario using the task description
    task_desc = record.get("task_description", "")
    scenario = Scenario(
        description=task_desc[:200] if task_desc else "(no description)",
        tests=None,
        rollouts=rollouts,
    )
    repo_id = record.get("repo_id", "")
    desc = task_desc
    if repo_id:
        desc = f"[{repo_id}] {desc}"
    return CWERecord(
        cwe_id=record["task_id"],
        cwe_description=desc,
        scenarios=[scenario],
        display_prefix="",
    )


def load_data(
    path: Path,
) -> tuple[list[CWERecord], dict[str, Any] | None]:
    """Load JSONL file into domain model.

    Returns (cwe_records, config_record).
    """
    config = read_config_record(path)
    records = read_data_records(path)
    cwes = []
    for record in records:
        if "task_id" in record:
            cwes.append(_load_record_swechat_format(record))
        elif "scenarios" in record:
            cwes.append(_load_record_new_format(record))
        elif "samples" in record:
            cwes.append(_load_record_old_format(record))
    return cwes, config


# ---------------------------------------------------------------------------
# Save screen (modal)
# ---------------------------------------------------------------------------


class SaveScreen(ModalScreen[str | None]):
    """Modal for saving code/tests to a file."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, default_path: str, content: str) -> None:
        super().__init__()
        self._default_path = default_path
        self._content = content

    def compose(self) -> ComposeResult:
        with Vertical(id="save-dialog"):
            yield Label("Save to file:")
            yield Input(value=self._default_path, id="save-input")

    def on_mount(self) -> None:
        self.query_one("#save-input", Input).focus()

    @on(Input.Submitted, "#save-input")
    def on_submit(self, event: Input.Submitted) -> None:
        filepath = event.value.strip()
        if filepath:
            try:
                Path(filepath).write_text(self._content)
                self.dismiss(filepath)
            except OSError as e:
                self.app.notify(f"Error saving: {e}", severity="error")
                self.dismiss(None)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class SavePairScreen(ModalScreen[str | None]):
    """Modal for saving code+test pair to a directory."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, default_dir: str, code: str, tests: str, solution_file: str = "solution.py", test_file: str = "test_solution.py", language: str = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self._default_dir = default_dir
        self._code = code
        self._tests = tests
        self._solution_file = solution_file
        self._test_file = test_file
        self._language = language

    def compose(self) -> ComposeResult:
        with Vertical(id="save-pair-dialog"):
            yield Label("Save pair to directory:")
            yield Input(value=self._default_dir, id="save-pair-input")
            yield Label(
                f"Writes {self._solution_file} and {self._test_file}",
                classes="hint-label",
            )

    def on_mount(self) -> None:
        self.query_one("#save-pair-input", Input).focus()

    @on(Input.Submitted, "#save-pair-input")
    def on_submit(self, event: Input.Submitted) -> None:
        dirpath = event.value.strip()
        if dirpath:
            try:
                d = Path(dirpath)
                d.mkdir(parents=True, exist_ok=True)
                (d / self._solution_file).write_text(self._code)
                # TODO: jank branch code duplication that preserves python-specific behavior
                if self._language == "python":
                    header = build_script_header(self._code, self._tests)
                    footer = build_script_footer()
                    (d / self._test_file).write_text(header + self._tests + footer)
                else:
                    (d / self._test_file).write_text(self._tests)
                self.dismiss(dirpath)
            except OSError as e:
                self.app.notify(f"Error saving: {e}", severity="error")
                self.dismiss(None)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class PytestCommandScreen(ModalScreen[None]):
    """Modal showing a copyable pytest command."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("enter", "close", "Close"),
    ]

    def __init__(self, command: str) -> None:
        super().__init__()
        self._command = command

    def compose(self) -> ComposeResult:
        with Vertical(id="pytest-dialog"):
            yield Label("Run tests with:")
            yield Input(
                value=self._command,
                id="pytest-input",
                select_on_focus=True,
            )
            yield Button("Copy to clipboard", id="copy-btn")
            yield Label(
                "Press Escape or Enter to close",
                classes="hint-label",
            )

    def on_mount(self) -> None:
        self.query_one("#pytest-input", Input).focus()

    @on(Button.Pressed, "#copy-btn")
    def on_copy(self, event: Button.Pressed) -> None:
        self.app.copy_to_clipboard(self._command)
        self.app.notify("Copied to clipboard")

    def action_close(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# Tree widget with vim bindings
# ---------------------------------------------------------------------------


class CWETree(Tree[NodeData]):
    """Tree widget with vim-style navigation."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("l", "expand_or_enter", "Expand", show=False),
        Binding("h", "collapse_or_parent", "Collapse", show=False),
        Binding("g", "scroll_home", "Top", show=False),
        Binding("G", "scroll_end", "Bottom", show=False),
    ]

    def action_expand_or_enter(self) -> None:
        if self.cursor_node is not None:
            if not self.cursor_node.is_expanded:
                self.cursor_node.expand()
            elif self.cursor_node.children:
                self.cursor_node.children[0].focus()
                self.select_node(self.cursor_node.children[0])
                self.action_cursor_down()

    def action_collapse_or_parent(self) -> None:
        if self.cursor_node is not None:
            if self.cursor_node.is_expanded:
                self.cursor_node.collapse()
            elif self.cursor_node.parent is not None:
                node = self.cursor_node.parent
                self.select_node(node)
                self.scroll_to_node(node)


# ---------------------------------------------------------------------------
# Main TUI app
# ---------------------------------------------------------------------------

APP_CSS = """
#main-container {
    height: 1fr;
}

#tree-pane {
    width: 30%;
    min-width: 30;
    border-right: solid $accent;
    overflow-y: auto;
}

#detail-pane {
    width: 70%;
    overflow-y: auto;
    padding: 1 2;
}

#save-dialog {
    width: 60;
    height: auto;
    max-height: 10;
    border: thick $accent;
    background: $surface;
    padding: 1 2;
    align: center middle;
}

#save-dialog Label {
    margin-bottom: 1;
}

.detail-title {
    text-style: bold;
    margin-bottom: 1;
}

.detail-section {
    margin-top: 1;
    margin-bottom: 1;
}

.code-viewer {
    height: auto;
    max-height: 50;
    margin-bottom: 1;
}

.stats-label {
    margin-bottom: 1;
}

DataTable {
    height: auto;
    max-height: 15;
}

#save-pair-dialog {
    width: 60;
    height: auto;
    max-height: 12;
    border: thick $accent;
    background: $surface;
    padding: 1 2;
    align: center middle;
}

#save-pair-dialog Label {
    margin-bottom: 1;
}

#pytest-dialog {
    width: 80;
    height: auto;
    max-height: 10;
    border: thick $accent;
    background: $surface;
    padding: 1 2;
    align: center middle;
}

#pytest-dialog Label {
    margin-bottom: 1;
}

#copy-btn {
    margin: 1 0;
}

.hint-label {
    color: $text-muted;
    text-style: italic;
}
"""


def _sort_key(value: object) -> tuple[int, float | str]:
    """Sort key for DataTable cells: numeric values first, then strings."""
    if isinstance(value, Text):
        raw = value.plain
    else:
        raw = str(value)
    raw = raw.strip().rstrip("%")
    try:
        return (0, float(raw))
    except (ValueError, TypeError):
        return (1, raw.lower())


class ExploreApp(App[None]):
    """TUI for exploring sf generate output."""

    CSS = APP_CSS

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "save", "Save"),
        Binding("S", "save_pair", "Save pair"),
        Binding("question_mark", "help", "Help"),
        Binding("tab", "toggle_focus", "Focus"),
        Binding("escape", "focus_tree", "Tree", show=False),
    ]

    def __init__(
        self,
        cwes: list[CWERecord],
        config: dict[str, Any] | None,
        file_path: str,
    ) -> None:
        super().__init__()
        self._cwes = cwes
        self._config = config
        self._file_path = file_path
        self._sort_column: object = None
        self._sort_reverse: bool = False
        # Detect language from config record, default to python
        self._language = DEFAULT_LANGUAGE
        if config:
            cfg = config.get("config", {})
            lang = cfg.get("language")
            if lang:
                self._language = lang
        try:
            self._lang_config = get_language_config(self._language)
        except ValueError:
            self._lang_config = get_language_config(DEFAULT_LANGUAGE)

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-container"):
            tree = CWETree("Results", id="nav-tree")
            tree.root.data = NodeData(kind=NodeKind.ROOT)
            yield tree
            with VerticalScroll(id="detail-pane"):
                yield Static("Select a node to view details.", id="detail-content")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"SecureForge Explorer"
        self.sub_title = self._file_path
        self._populate_tree()
        tree = self.query_one("#nav-tree", CWETree)
        tree.focus()
        # Show root summary on start
        self._show_root_view()

    def _populate_tree(self) -> None:
        self._cwes.sort(key=lambda c: str(c.cwe_id))
        tree = self.query_one("#nav-tree", CWETree)
        root = tree.root
        total_r = sum(c.total_rollouts for c in self._cwes)
        root.set_label(f"Results ({len(self._cwes)} records, {total_r} rollouts)")
        root.data = NodeData(kind=NodeKind.ROOT)

        for ci, cwe in enumerate(self._cwes):
            ns = len(cwe.scenarios)
            nr = cwe.total_rollouts
            cwe_label = (
                f"{cwe.display_label} "
                f"({ns} Scenario{'s' if ns != 1 else ''}, "
                f"{nr} Rollout{'s' if nr != 1 else ''})"
            )
            cwe_node = root.add(
                cwe_label,
                data=NodeData(kind=NodeKind.CWE, cwe_idx=ci),
            )
            for si, scenario in enumerate(cwe.scenarios):
                desc_short = scenario.description[:50]
                if len(scenario.description) > 50:
                    desc_short += "..."
                nr_s = len(scenario.rollouts)
                s_label = (
                    f"S{si + 1}: {desc_short} "
                    f"({nr_s} Rollout{'s' if nr_s != 1 else ''})"
                )
                s_node = cwe_node.add(
                    s_label,
                    data=NodeData(
                        kind=NodeKind.SCENARIO, cwe_idx=ci, scenario_idx=si
                    ),
                )
                for ri, rollout in enumerate(scenario.rollouts):
                    nv = len(rollout.vulnerabilities)
                    td = rollout.test_details
                    if td is not None:
                        label_text = (
                            f"R{ri + 1}: "
                            f"{td.num_passed}/{td.num_tests} tests, "
                            f"{nv} vuln{'s' if nv != 1 else ''}"
                        )
                    else:
                        label_text = (
                            f"R{ri + 1}: {nv} "
                            f"vulnerabilit{'y' if nv == 1 else 'ies'}"
                        )
                    if rollout.passes_tests is True:
                        color = "green"
                    elif rollout.passes_tests is False:
                        color = "red"
                    else:
                        color = "grey70"
                    r_label = Text(label_text, style=color)
                    s_node.add_leaf(
                        r_label,
                        data=NodeData(
                            kind=NodeKind.ROLLOUT,
                            cwe_idx=ci,
                            scenario_idx=si,
                            rollout_idx=ri,
                        ),
                    )

        root.expand()

    # ----- Detail panel builders -----

    def _clear_detail(self) -> None:
        container = self.query_one("#detail-pane", VerticalScroll)
        container.remove_children()

    def _show_root_view(self) -> None:
        self._clear_detail()
        container = self.query_one("#detail-pane", VerticalScroll)

        container.mount(Static("Summary", classes="detail-title"))

        # Config info
        if self._config:
            cfg = self._config.get("config", {})
            info_lines = []
            for key in ("model", "temperature", "analysis_tool", "test_model", "num_rollouts"):
                if key in cfg:
                    info_lines.append(f"  {key}: {cfg[key]}")
            if info_lines:
                container.mount(Static("Configuration:\n" + "\n".join(info_lines), classes="stats-label"))

            env = self._config.get("environment", {})
            if env:
                env_lines = [f"  {k}: {v}" for k, v in env.items()]
                container.mount(Static("Environment:\n" + "\n".join(env_lines), classes="stats-label"))

        # Aggregate stats
        all_rollouts = _collect_all_rollouts(self._cwes)
        stats = _compute_rollout_stats(all_rollouts)
        total_scenarios = sum(len(c.scenarios) for c in self._cwes)

        header = f"Records: {len(self._cwes)}  |  Scenarios: {total_scenarios}"
        container.mount(Static(header, classes="stats-label"))
        container.mount(Static(_format_stats_block(stats), classes="stats-label"))

        # Summary table
        table = DataTable()
        col_keys = table.add_columns(
            "ID", "Scenarios", "Rollouts", "Pass", "Fail",
            "Test Pass Rate",
            "Vuln Rate", "Vuln Rate (Tests Pass)", "Vuln Rate (Tests Fail)",
            "Sev Avg", "Sev Min", "Sev Max",
        )
        for cwe in self._cwes:
            cwe_rollouts = [r for s in cwe.scenarios for r in s.rollouts]
            cs = _compute_rollout_stats(cwe_rollouts)
            table.add_row(
                cwe.display_label,
                str(len(cwe.scenarios)),
                str(cs["total"]),
                str(cs["passing"]),
                str(cs["failing"]),
                cs["test_pass_rate"],
                cs["vuln_rate"],
                cs["vuln_rate_passing"],
                cs["vuln_rate_failing"],
                cs["severity_avg"],
                cs["severity_min"],
                cs["severity_max"],
            )
        container.mount(Static("Overview:", classes="detail-section"))
        container.mount(table)
        table.sort(col_keys[6], key=_sort_key, reverse=True)

    def _show_cwe_view(self, cwe_idx: int) -> None:
        self._clear_detail()
        container = self.query_one("#detail-pane", VerticalScroll)
        cwe = self._cwes[cwe_idx]

        container.mount(Static(cwe.display_label, classes="detail-title"))
        container.mount(Static(cwe.cwe_description, classes="stats-label"))

        # Aggregate stats for this CWE
        cwe_rollouts = [r for s in cwe.scenarios for r in s.rollouts]
        stats = _compute_rollout_stats(cwe_rollouts)
        container.mount(Static(_format_stats_block(stats), classes="stats-label"))

        # Scenario table
        table = DataTable()
        col_keys = table.add_columns(
            "#", "Description", "Rollouts", "Pass", "Fail",
            "Test Pass Rate",
            "Vuln Rate", "Vuln Rate (Tests Pass)", "Vuln Rate (Tests Fail)",
            "Sev Avg", "Sev Min", "Sev Max",
        )
        for si, scenario in enumerate(cwe.scenarios):
            desc = scenario.description[:50]
            if len(scenario.description) > 50:
                desc += "..."
            ss = _compute_rollout_stats(scenario.rollouts)
            table.add_row(
                str(si + 1), desc, str(ss["total"]),
                str(ss["passing"]), str(ss["failing"]),
                ss["test_pass_rate"],
                ss["vuln_rate"], ss["vuln_rate_passing"], ss["vuln_rate_failing"],
                ss["severity_avg"], ss["severity_min"], ss["severity_max"],
            )
        container.mount(Static("Scenarios:", classes="detail-section"))
        container.mount(table)
        table.sort(col_keys[6], key=_sort_key, reverse=True)

    def _show_scenario_view(self, cwe_idx: int, scenario_idx: int) -> None:
        self._clear_detail()
        container = self.query_one("#detail-pane", VerticalScroll)
        cwe = self._cwes[cwe_idx]
        scenario = cwe.scenarios[scenario_idx]

        # Build header with test count if available
        header = f"{cwe.display_label} / Scenario {scenario_idx + 1}"
        test_counts = [
            r.test_details for r in scenario.rollouts if r.test_details is not None
        ]
        if test_counts:
            # Use max num_tests across rollouts as the scenario's test count
            n_tests = max(td.num_tests for td in test_counts)
            header += f" ({n_tests} test{'s' if n_tests != 1 else ''})"

        container.mount(Static(header, classes="detail-title"))
        container.mount(Static(scenario.description, classes="stats-label"))

        # Stats for this scenario
        stats = _compute_rollout_stats(scenario.rollouts)
        container.mount(Static(_format_stats_block(stats), classes="stats-label"))

        # Test code viewer
        if scenario.tests:
            container.mount(Static("Tests:", classes="detail-section"))
            code_area = TextArea(
                scenario.tests,
                language=self._lang_config.code_fence,
                theme="monokai",
                show_line_numbers=True,
                read_only=True,
                classes="code-viewer",
            )
            container.mount(code_area)
        else:
            container.mount(
                Static("Tests: (none)", classes="detail-section")
            )

        # Rollout table
        table = DataTable()
        col_keys = table.add_columns(
            "#", "Status", "Passed", "Failed", "Test Pass Rate",
            "Vulns", "Sev Avg", "Lines",
        )
        for ri, rollout in enumerate(scenario.rollouts):
            status = "?"
            if rollout.passes_tests is True:
                status = "PASS"
            elif rollout.passes_tests is False:
                status = "FAIL"
            td = rollout.test_details
            passed_str = str(td.num_passed) if td else "-"
            failed_str = str(td.num_failed) if td else "-"
            pass_rate = _vuln_rate(td.num_passed, td.num_tests) if td else "-"
            line_count = rollout.code.count("\n") + 1
            sev = _severity_stats([rollout])
            table.add_row(
                str(ri + 1),
                status,
                passed_str,
                failed_str,
                pass_rate,
                str(len(rollout.vulnerabilities)),
                sev["severity_avg"],
                str(line_count),
            )
        container.mount(Static("Rollouts:", classes="detail-section"))
        container.mount(table)
        table.sort(col_keys[5], key=_sort_key, reverse=True)

    def _show_rollout_view(
        self, cwe_idx: int, scenario_idx: int, rollout_idx: int
    ) -> None:
        self._clear_detail()
        container = self.query_one("#detail-pane", VerticalScroll)
        cwe = self._cwes[cwe_idx]
        scenario = cwe.scenarios[scenario_idx]
        rollout = scenario.rollouts[rollout_idx]

        container.mount(
            Static(
                f"{cwe.display_label} / S{scenario_idx + 1} / "
                f"R{rollout_idx + 1}",
                classes="detail-title",
            )
        )

        # Status summary
        td = rollout.test_details
        if td is not None:
            test_status = (
                f"Tests: {td.num_passed}/{td.num_tests} passed"
                + (f", {td.num_failed} failed" if td.num_failed else "")
            )
        elif rollout.passes_tests is True:
            test_status = "Tests: PASS"
        elif rollout.passes_tests is False:
            test_status = "Tests: FAIL"
        else:
            test_status = "Tests: N/A (no tests)"

        vuln_status = (
            f"Vulnerabilities: {len(rollout.vulnerabilities)} finding"
            f"{'s' if len(rollout.vulnerabilities) != 1 else ''}"
        )
        line_count = rollout.code.count("\n") + 1
        summary = f"{test_status}  |  {vuln_status}  |  {line_count} lines"
        container.mount(Static(summary, classes="stats-label"))

        # Code viewer
        container.mount(Static("Code:", classes="detail-section"))
        code_area = TextArea(
            rollout.code,
            language=self._lang_config.code_fence,
            theme="monokai",
            show_line_numbers=True,
            read_only=True,
            classes="code-viewer",
        )
        container.mount(code_area)

        # Per-test results table
        if td is not None and td.results:
            test_table = DataTable()
            test_table.add_columns("Test", "Status")
            for tr in td.results:
                status_text = Text(
                    tr.status.upper(),
                    style="green" if tr.status == "passed" else "red",
                )
                test_table.add_row(tr.name, status_text)
            container.mount(
                Static(
                    f"Test Results ({len(td.results)}):",
                    classes="detail-section",
                )
            )
            container.mount(test_table)

        # Vulnerability table
        if rollout.vulnerabilities:
            table = DataTable()
            table.add_columns("Rule", "Message", "Line", "Severity", "Analyzer")
            for v in rollout.vulnerabilities:
                table.add_row(
                    v.rule,
                    v.message[:80],
                    str(v.line) if v.line else "-",
                    f"{v.security_severity:.1f}" if v.security_severity is not None else "-",
                    v.analyzer,
                )
            container.mount(
                Static(
                    f"Vulnerabilities ({len(rollout.vulnerabilities)}):",
                    classes="detail-section",
                )
            )
            container.mount(table)
        else:
            container.mount(
                Static("No vulnerabilities found.", classes="detail-section")
            )

    # ----- Event handlers -----

    @on(Tree.NodeHighlighted, "#nav-tree")
    def on_tree_highlight(self, event: Tree.NodeHighlighted[NodeData]) -> None:
        data = event.node.data
        if data is None:
            return
        if data.kind == NodeKind.ROOT:
            self._show_root_view()
        elif data.kind == NodeKind.CWE and data.cwe_idx is not None:
            self._show_cwe_view(data.cwe_idx)
        elif (
            data.kind == NodeKind.SCENARIO
            and data.cwe_idx is not None
            and data.scenario_idx is not None
        ):
            self._show_scenario_view(data.cwe_idx, data.scenario_idx)
        elif (
            data.kind == NodeKind.ROLLOUT
            and data.cwe_idx is not None
            and data.scenario_idx is not None
            and data.rollout_idx is not None
        ):
            self._show_rollout_view(
                data.cwe_idx, data.scenario_idx, data.rollout_idx
            )

    @on(DataTable.HeaderSelected)
    def on_header_selected(self, event: DataTable.HeaderSelected) -> None:
        table = event.data_table
        col_key = event.column_key
        if self._sort_column == col_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = col_key
            self._sort_reverse = False
        table.sort(col_key, key=_sort_key, reverse=self._sort_reverse)

    # ----- Actions -----

    def _get_current_node_data(self) -> NodeData | None:
        tree = self.query_one("#nav-tree", CWETree)
        if tree.cursor_node is not None:
            return tree.cursor_node.data
        return None

    def action_save(self) -> None:
        data = self._get_current_node_data()
        if data is None:
            self.notify("No node selected", severity="warning")
            return

        ext = self._lang_config.extension
        content: str | None = None
        default_name = f"output{ext}"

        if data.kind == NodeKind.ROLLOUT:
            cwe = self._cwes[data.cwe_idx]  # type: ignore[index]
            scenario = cwe.scenarios[data.scenario_idx]  # type: ignore[index]
            rollout = scenario.rollouts[data.rollout_idx]  # type: ignore[index]
            content = rollout.code
            safe_id = str(cwe.cwe_id).replace("/", "_")[:40]
            default_name = (
                f"{safe_id}_s{data.scenario_idx + 1}"  # type: ignore[operator]
                f"_r{data.rollout_idx + 1}{ext}"  # type: ignore[operator]
            )
        elif data.kind == NodeKind.SCENARIO:
            cwe = self._cwes[data.cwe_idx]  # type: ignore[index]
            scenario = cwe.scenarios[data.scenario_idx]  # type: ignore[index]
            if scenario.tests:
                content = scenario.tests
                safe_id = str(cwe.cwe_id).replace("/", "_")[:40]
                default_name = (
                    f"{safe_id}_s{data.scenario_idx + 1}_tests{ext}"  # type: ignore[operator]
                )
            else:
                self.notify("No tests to save for this scenario", severity="warning")
                return
        else:
            self.notify("Select a rollout or scenario to save", severity="warning")
            return

        def on_dismiss(result: str | None) -> None:
            if result:
                self.notify(f"Saved to {result}")

        self.push_screen(SaveScreen(default_name, content), on_dismiss)

    def action_save_pair(self) -> None:
        data = self._get_current_node_data()
        if data is None or data.kind != NodeKind.ROLLOUT:
            self.notify("Select a rollout to save pair", severity="warning")
            return

        cwe = self._cwes[data.cwe_idx]  # type: ignore[index]
        scenario = cwe.scenarios[data.scenario_idx]  # type: ignore[index]
        rollout = scenario.rollouts[data.rollout_idx]  # type: ignore[index]

        if not scenario.tests:
            self.notify("No tests available for this scenario", severity="warning")
            return

        safe_id = str(cwe.cwe_id).replace("/", "_")[:40]
        default_dir = (
            f"{safe_id}_s{data.scenario_idx + 1}"  # type: ignore[operator]
            f"_r{data.rollout_idx + 1}"  # type: ignore[operator]
        )

        solution_file = self._lang_config.solution_file
        test_file = self._lang_config.test_file

        def on_dismiss(result: str | None) -> None:
            if result:
                self.notify(f"Saved pair to {result}/")
                # TODO: jank branch code duplication that preserves python-specific behavior
                if self._language == "python":
                    cmd = f"uv run {result}/{test_file}"
                else:
                    test_runner = " ".join(self._lang_config.test_runner)
                    cmd = f"{test_runner} {result}/{test_file}"
                self.push_screen(PytestCommandScreen(cmd))

        self.push_screen(
            SavePairScreen(default_dir, rollout.code, scenario.tests, solution_file, test_file, language=self._language),
            on_dismiss,
        )

    def action_toggle_focus(self) -> None:
        tree = self.query_one("#nav-tree", CWETree)
        detail = self.query_one("#detail-pane", VerticalScroll)
        if tree.has_focus:
            detail.focus()
        else:
            tree.focus()

    def action_focus_tree(self) -> None:
        self.query_one("#nav-tree", CWETree).focus()

    def action_help(self) -> None:
        self.notify(
            "j/k: up/down | h/l: collapse/expand | "
            "g/G: top/bottom | s: save | S: save pair | "
            "tab: toggle focus | q: quit",
            timeout=8,
        )


# ---------------------------------------------------------------------------
# Typer command
# ---------------------------------------------------------------------------


@app.command()
def explore(
    path: Path = typer.Argument(..., help="Path to a JSONL output file"),
) -> None:
    """Interactively explore sf generate output."""
    if not path.exists():
        typer.echo(f"File not found: {path}", err=True)
        raise typer.Exit(1)

    cwes, config = load_data(path)
    if not cwes:
        typer.echo("No records found in file.", err=True)
        raise typer.Exit(1)

    tui_app = ExploreApp(cwes, config, str(path))
    tui_app.run()

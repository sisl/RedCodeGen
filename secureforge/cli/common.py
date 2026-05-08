from pathlib import Path
from typing import Any

import jsonlines


def is_data_record(record: dict[str, Any]) -> bool:
    """Return True if the record is a data record (not a config metadata line)."""
    return record.get("record_type") != "config"


def read_data_records(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL file and return only data records (skipping config lines)."""
    with jsonlines.open(path) as reader:
        return [record for record in reader if is_data_record(record)]


def read_config_record(path: Path) -> dict[str, Any] | None:
    """Read a JSONL file and return the config record, or None if not present."""
    with jsonlines.open(path) as reader:
        for record in reader:
            if record.get("record_type") == "config":
                return record
    return None


def normalize_record_samples(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize a generate record into a flat list of samples.

    Handles both the old format (record["samples"] with "evaluation")
    and the new format (record["scenarios"][*]["rollouts"][*] with "vulnerabilities").

    Returns:
        List of dicts with keys: scenario, code, evaluation
    """
    if "samples" in record:
        return record["samples"]

    samples = []
    for scenario_group in record.get("scenarios", []):
        scenario_text = scenario_group["scenario"]
        for rollout in scenario_group.get("rollouts", []):
            samples.append({
                "scenario": scenario_text,
                "code": rollout["code"],
                "evaluation": rollout.get("vulnerabilities", []),
            })
    return samples

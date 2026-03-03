from typing import Any


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

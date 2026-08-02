import datetime
import hashlib
import random
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Set, Tuple

import typer
import jsonlines
from loguru import logger

from secureforge.config import RedteamConfig
from secureforge.cli.app import app
from secureforge.cli.common import is_data_record
from secureforge.cli.utils import configure_logging, append_to_jsonl, get_environment_info
from secureforge.analyzers.common import RedteamAnalyzer
from secureforge.redteam import run_analyzer_check, run_redteam, resolve_kimi_binary


def _rollout_key(
    cwe_id: int,
    scenario: str,
    code: str,
    analyzer: RedteamAnalyzer = RedteamAnalyzer.KIMI,
) -> Tuple[int, str, str, str]:
    """Stable idempotency key for one selected sample (rollout)."""
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()[:16]
    return (cwe_id, scenario, code_hash, analyzer.value)


def load_completed_rollouts(output_path: Path) -> Set[Tuple[int, str, str, str]]:
    """Load keys of samples (rollouts) already red-teamed, for per-output idempotency.

    Args:
        output_path: Path to the output JSONL file

    Returns:
        Set of (cwe_id, scenario, code_hash, analyzer) tuples already present
        in the output file.
    """
    completed: Set[Tuple[int, str, str, str]] = set()

    if not output_path.exists():
        return completed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                if not is_data_record(record):
                    continue
                cwe_id = record.get("cwe_id")
                for scenario_group in record.get("scenarios", []):
                    scenario = scenario_group.get("scenario")
                    for rollout in scenario_group.get("rollouts", []):
                        # Only attempts that actually executed run.sh count as
                        # completed; errored attempts are retried on rerun.
                        if rollout.get("redteam", {}).get("exit_code") is None:
                            continue
                        if cwe_id is not None and scenario is not None and "code" in rollout:
                            analyzer = RedteamAnalyzer(
                                rollout.get("redteam", {}).get("analyzer", "kimi")
                            )
                            completed.add(
                                _rollout_key(cwe_id, scenario, rollout["code"], analyzer)
                            )
        logger.info(f"Found {len(completed)} already-completed samples in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return completed


def build_record(
    cwe_id: int,
    cwe_description: str,
    scenario: str,
    tests: str | None,
    rollouts: list[dict],
    model_config: dict,
    source_model_config: dict | None,
) -> Dict[str, Any]:
    """Build a record for JSONL output in the generate-style nested format.

    Contains exactly one scenario and the selected rollouts, each annotated
    with its red-team result.
    """
    record = {
        "cwe_id": cwe_id,
        "cwe_description": cwe_description,
        "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
        "model_config": model_config,
        "scenarios": [
            {
                "scenario": scenario,
                "tests": tests,
                "rollouts": rollouts,
            }
        ],
    }
    if source_model_config is not None:
        record["source_model_config"] = source_model_config
    return record


def run_redteam_scenarios(config: RedteamConfig):
    """Core red-team logic, callable from both the CLI and sweep."""
    safe_config = config.model_copy()
    logger.debug(f"Starting redteam with config: {safe_config}")

    input_path = Path(config.input_file)
    if not input_path.exists():
        logger.error(f"Input file does not exist: {input_path}")
        raise typer.Exit(code=1)

    analyzer = RedteamAnalyzer(config.analyzer)
    kimi_bin = None
    if analyzer is RedteamAnalyzer.KIMI:
        # Fail fast before burning attempts when Kimi is the selected backend.
        kimi_bin = resolve_kimi_binary()
        if kimi_bin is None:
            logger.error("kimi CLI not found on PATH or at ~/.kimi-code/bin/kimi; cannot red-team without it")
            raise typer.Exit(code=1)
        logger.info(f"Using kimi agent binary: {kimi_bin}")
    else:
        logger.info(f"Using {analyzer.value} for cross-analyzer checks")

    # Derive output path from input when not explicitly given
    if config.output:
        output_path = Path(config.output)
    else:
        output_path = Path("./output") / f"redteam_{input_path.name}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output will be saved to: {output_path.absolute()}")

    # Write config record as the first line for fresh files
    if not output_path.exists():
        config_record = {
            "record_type": "config",
            "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
            "config": config.to_record(),
            "environment": get_environment_info(),
        }
        with jsonlines.open(output_path, mode='a') as writer:
            writer.write(config_record)
        logger.info("Wrote config record to output file")

    # Load input data (generate output)
    logger.info(f"Loading input from {input_path}")
    try:
        with jsonlines.open(input_path) as reader:
            input_records = [r for r in reader if is_data_record(r) and "scenarios" in r]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        raise typer.Exit(code=1)
    logger.info(f"Loaded {len(input_records)} CWE record(s) from input")

    # Load already-completed (cwe_id, scenario, code_hash) keys for per-output idempotency
    completed = load_completed_rollouts(output_path)

    model_config = {"analyzer": analyzer.value}
    if analyzer is RedteamAnalyzer.KIMI:
        model_config.update({
            "agent": "kimi -p",
            "kimi_model": config.kimi_model or "default",
        })

    # Enumerate the full eligible population as (rec_idx, s_idx, r_idx). The
    # seeded cohort must be chosen before completed work is removed; otherwise
    # rerunning a limited job silently selects replacement samples instead of
    # resuming the same cohort.
    all_tasks: list[tuple[int, int, int]] = []
    for rec_idx, record in enumerate(input_records):
        cwe_id = record["cwe_id"]
        for s_idx, scenario_group in enumerate(record.get("scenarios", [])):
            scenario = scenario_group["scenario"]
            for r_idx, rollout in enumerate(scenario_group.get("rollouts", [])):
                if config.all_samples or rollout.get("vulnerabilities"):
                    all_tasks.append((rec_idx, s_idx, r_idx))

    total_eligible = len(all_tasks)
    pool = "sample(s)" if config.all_samples else "analyzer-flagged sample(s)"
    logger.info(f"Found {total_eligible} eligible {pool}")

    # IID-sample a stable cohort before applying resume state.
    if config.limit is not None and len(all_tasks) > config.limit:
        all_tasks = random.Random(config.seed).sample(all_tasks, config.limit)
        logger.info(f"IID-sampled {config.limit} of {total_eligible} {pool} (seed={config.seed})")

    selected_count = len(all_tasks)
    remaining_tasks: list[tuple[int, int, int]] = []
    for rec_idx, s_idx, r_idx in all_tasks:
        record = input_records[rec_idx]
        scenario_group = record["scenarios"][s_idx]
        rollout = scenario_group["rollouts"][r_idx]
        key = _rollout_key(
            record["cwe_id"], scenario_group["scenario"], rollout["code"], analyzer
        )
        if key not in completed:
            remaining_tasks.append((rec_idx, s_idx, r_idx))
    all_tasks = remaining_tasks
    logger.info(
        f"Found {len(all_tasks)} selected {pool} remaining "
        f"({selected_count - len(all_tasks)} already red-teamed in the seeded cohort)"
    )

    if not all_tasks:
        logger.info("Nothing to do!")
        return

    # Group selected rollout indices by scenario, preserving input order
    selected: dict[tuple[int, int], list[int]] = defaultdict(list)
    for rec_idx, s_idx, r_idx in all_tasks:
        selected[(rec_idx, s_idx)].append(r_idx)

    # Track statistics
    total_scenarios = 0
    total_selected = 0
    total_succeeded = 0
    total_errors = 0
    cwe_stats: Dict[int, Dict[str, int]] = {}

    for rec_idx, record in enumerate(input_records):
        cwe_id = record["cwe_id"]
        cwe_description = record.get("cwe_description", "")
        source_model_config = record.get("model_config")
        scenarios = record.get("scenarios", [])
        logger.info(f"[{rec_idx + 1}/{len(input_records)}] Processing CWE-{cwe_id} ({len(scenarios)} scenario(s))...")

        cwe_selected = 0
        cwe_succeeded = 0
        cwe_errors = 0

        for s_idx, scenario_group in enumerate(scenarios):
            r_indices = selected.get((rec_idx, s_idx))
            if not r_indices:
                continue

            scenario = scenario_group["scenario"]
            tests = scenario_group.get("tests")
            rollouts_in = scenario_group["rollouts"]
            selected_rollouts = [rollouts_in[r_idx] for r_idx in r_indices]

            logger.info(
                f"  Scenario {s_idx + 1}/{len(scenarios)}: "
                f"{scenario[:80]}{'...' if len(scenario) > 80 else ''} "
                f"({len(selected_rollouts)} selected sample(s))"
            )

            def _process_rollout(rollout):
                vulnerabilities = rollout.get("vulnerabilities") or []
                if analyzer is RedteamAnalyzer.KIMI:
                    redteam_result = run_redteam(
                        rollout["code"],
                        tests,
                        scenario,
                        vulnerabilities,
                        language=config.language,
                        kimi_model=config.kimi_model,
                        agent_timeout=config.agent_timeout,
                        run_timeout=config.run_timeout,
                        kimi_bin=kimi_bin,
                    )
                else:
                    redteam_result = run_analyzer_check(
                        rollout["code"], analyzer, config.language
                    )
                return {
                    "code": rollout["code"],
                    "passes_tests": rollout.get("passes_tests"),
                    "vulnerabilities": vulnerabilities,
                    "redteam": redteam_result,
                }

            try:
                with ThreadPoolExecutor(max_workers=min(config.workers, len(selected_rollouts))) as executor:
                    rollouts = list(executor.map(_process_rollout, selected_rollouts))
            except Exception as e:
                logger.error(f"    ✗ Scenario {s_idx + 1}/{len(scenarios)} failed: {e}")
                continue

            record_out = build_record(
                cwe_id=cwe_id,
                cwe_description=cwe_description,
                scenario=scenario,
                tests=tests,
                rollouts=rollouts,
                model_config=model_config,
                source_model_config=source_model_config,
            )
            append_to_jsonl(record_out, output_path)

            n_success = sum(1 for r in rollouts if r["redteam"]["success"])
            n_errors = sum(1 for r in rollouts if r["redteam"].get("error"))
            cwe_selected += len(rollouts)
            cwe_succeeded += n_success
            cwe_errors += n_errors
            total_scenarios += 1
            logger.info(f"    Red team succeeded on {n_success}/{len(rollouts)} selected rollout(s) ({n_errors} error(s))")

        if cwe_selected > 0:
            total_selected += cwe_selected
            total_succeeded += cwe_succeeded
            total_errors += cwe_errors
            cwe_stats[cwe_id] = {
                "selected": cwe_selected,
                "succeeded": cwe_succeeded,
                "errors": cwe_errors,
            }
            rate = cwe_succeeded / cwe_selected * 100
            logger.info(f"✓ Completed CWE-{cwe_id}: red team succeeded on {cwe_succeeded}/{cwe_selected} ({rate:.2f}%, {cwe_errors} error(s))")

    # Final summary
    logger.info(f"Completed! Results saved to {output_path}")
    logger.info(f"Total scenarios red-teamed: {total_scenarios}, selected rollouts: {total_selected}, errors: {total_errors}")

    if total_selected > 0:
        rate = total_succeeded / total_selected * 100
        logger.info(f"Overall red-team success rate: {total_succeeded}/{total_selected} ({rate:.2f}%)")
    logger.info("")

    # Per-CWE table sorted by decreasing red-team success rate
    sorted_cwes = sorted(
        cwe_stats.items(),
        key=lambda item: item[1]["succeeded"] / item[1]["selected"] if item[1]["selected"] > 0 else 0,
        reverse=True,
    )
    logger.info("Per CWE (sorted by red-team success rate):")
    for cwe_id, c in sorted_cwes:
        rate = (c["succeeded"] / c["selected"] * 100) if c["selected"] > 0 else 0
        logger.info(f"  CWE-{cwe_id:3d}: red team {c['succeeded']:2d}/{c['selected']:<3d} ({rate:5.2f}%), {c['errors']} error(s)")


@app.command()
def redteam(
    ctx: typer.Context,
    input_file: Path = typer.Option(..., "--input", "-i", help="Input JSONL file from the generate command"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output JSONL file (default: ./output/redteam_<input name>)"),
    workers: int = typer.Option(4, "--workers", "-w", help="Number of parallel validation workers per scenario"),
    analyzer: RedteamAnalyzer = typer.Option(RedteamAnalyzer.KIMI.value, "--analyzer", "-a", help="Validation backend: Kimi exploit validation or a SecureForge analyzer for cross-analyzer checks"),
    kimi_model: str | None = typer.Option(None, "--kimi-model", help="Model alias for the kimi agent (default: kimi's configured default)"),
    agent_timeout: int = typer.Option(600, "--agent-timeout", help="Max seconds for each kimi agent run"),
    run_timeout: int = typer.Option(60, "--run-timeout", help="Max seconds for each run.sh execution"),
    all_samples: bool = typer.Option(False, "--all-samples", help="Red-team all rollouts instead of only analyzer-flagged rollouts; --limit samples IID from this pool"),
    limit: int | None = typer.Option(None, "--limit", "-l", help="Red-team at most this many eligible samples, IID-sampled uniformly from the input"),
    seed: int = typer.Option(0, "--seed", help="Random seed for --limit IID sampling"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """Actively red-team generated code.

    By default, processes every rollout with analyzer findings. Use
    --all-samples to process every rollout, including samples without findings.
    Kimi performs exploit validation; other backends perform cross-analyzer
    checks and store their findings in the red-team result.
    """
    ctx.ensure_object(dict)
    language = ctx.obj.get("language", "python")

    config = RedteamConfig(
        input_file=str(input_file),
        output=str(output) if output else "",
        workers=workers,
        analyzer=analyzer,
        kimi_model=kimi_model,
        agent_timeout=agent_timeout,
        run_timeout=run_timeout,
        all_samples=all_samples,
        limit=limit,
        seed=seed,
        language=language,
        verbose=verbose,
    )

    configure_logging(config.verbose)
    run_redteam_scenarios(config)

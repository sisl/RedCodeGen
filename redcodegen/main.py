"""
main.py
Main script for generating and evaluating vulnerable code samples
"""

import rich_click as click
import jsonlines
import logging
import dspy
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Any
from multiprocessing import Pool, Manager
from threading import Thread
from cwe2.database import Database

from redcodegen.constants import CWE_TOP_25, create_lm
from redcodegen.proposal import ProposalDistribution, GenerateRequest, Goal
from redcodegen.uncertainty import quantify

from rich.logging import RichHandler

# Setup logging for redcodegen only
redcodegen_logger = logging.getLogger("redcodegen")
redcodegen_logger.setLevel(logging.INFO)
redcodegen_logger.addHandler(RichHandler(rich_tracebacks=True))
logger = redcodegen_logger


def load_completed_cwes(output_path: Path) -> Set[int]:
    """Load CWE IDs that have already been processed.

    Args:
        output_path: Path to the output JSONL file

    Returns:
        Set of CWE IDs that are already in the output file
    """
    completed = set()

    if not output_path.exists():
        return completed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                if 'cwe_id' in record:
                    completed.add(record['cwe_id'])
        logger.info(f"Found {len(completed)} already-completed CWEs in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return completed


def load_completed_examples(output_path: Path) -> Set[str]:
    """Load example file hashes that have already been processed.

    Args:
        output_path: Path to the output JSONL file

    Returns:
        Set of example SHA256 hashes already in the output file
    """
    completed = set()

    if not output_path.exists():
        return completed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                example_hash = record.get("example_sha256")
                if example_hash:
                    completed.add(example_hash)
        logger.info(f"Found {len(completed)} already-completed examples in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return completed


def load_completed_patch_regenerations(output_path: Path) -> Set[tuple[str, str, str]]:
    """Load patch regenerations that have already been processed.

    Args:
        output_path: Path to the output JSONL file

    Returns:
        Set of (patch_sha256, file_path, example_sha256) tuples already in the output file
    """
    completed = set()

    if not output_path.exists():
        return completed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                patch_sha256 = record.get("patch_sha256")
                file_path = record.get("file_path")
                example_sha256 = record.get("example_sha256")
                if patch_sha256 and file_path and example_sha256:
                    completed.add((str(patch_sha256), str(file_path), str(example_sha256)))
        logger.info(f"Found {len(completed)} already-completed patch regenerations in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return completed


def get_model_config() -> Dict[str, Any]:
    """Extract model configuration from current DSPy settings.

    Returns:
        Dict with model configuration info
    """
    lm = dspy.settings.lm
    config = {
        "model": getattr(lm, 'model', 'unknown'),
    }

    return config


def build_record(
    cwe_id: int,
    cwe_name: str,
    cwe_description: str,
    scenarios: List[str],
    codes: List[str],
    evaluations: List[Any],
    errors: List[str],
    min_scenarios: int
) -> Dict[str, Any]:
    """Build a record for JSONL output.

    Args:
        cwe_id: CWE identifier
        cwe_name: CWE name
        cwe_description: CWE description
        scenarios: List of scenario descriptions
        codes: List of generated code samples
        evaluations: List of evaluation results (can contain None for failures)
        errors: List of error messages (None for successful evaluations)
        min_scenarios: Minimum scenarios parameter used

    Returns:
        Dict representing the complete record for this CWE
    """
    samples = []
    for scenario, code, evaluation, error in zip(scenarios, codes, evaluations, errors):
        samples.append({
            "scenario": scenario,
            "code": code,
            "evaluation": evaluation
        })

    return {
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "cwe_description": cwe_description,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "min_scenarios": min_scenarios,
        "samples": samples
    }


def build_example_record(
    example_path: str,
    example_sha256: str,
    scenarios: List[str],
    codes: List[str],
    evaluations: List[Any],
    min_scenarios: int
) -> Dict[str, Any]:
    """Build a record for example regeneration JSONL output.

    Args:
        example_path: Path to the source example (relative or absolute)
        example_sha256: SHA256 hash of the example contents
        scenarios: List of scenario descriptions
        codes: List of generated code samples
        evaluations: List of evaluation results (can contain None for failures)
        min_scenarios: Minimum scenarios parameter used

    Returns:
        Dict representing the complete record for this example
    """
    samples = []
    for scenario, code, evaluation in zip(scenarios, codes, evaluations):
        samples.append({
            "scenario": scenario,
            "code": code,
            "evaluation": evaluation
        })

    return {
        "example_path": example_path,
        "example_sha256": example_sha256,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "min_scenarios": min_scenarios,
        "samples": samples
    }


def build_patch_regenerate_record(
    instance_id: str,
    model: str,
    repo: str,
    base: str,
    resolved: str,
    patch_sha256: str,
    file_path: str,
    example_sha256: str,
    scenarios: List[str],
    codes: List[str],
    evaluations: List[Any],
    min_scenarios: int
) -> Dict[str, Any]:
    """Build a record for patch regeneration JSONL output."""
    samples = []
    for scenario, code, evaluation in zip(scenarios, codes, evaluations):
        samples.append({
            "scenario": scenario,
            "code": code,
            "evaluation": evaluation
        })

    return {
        "instance_id": instance_id,
        "model": model,
        "repo": repo,
        "base": base,
        "resolved": resolved,
        "patch_sha256": patch_sha256,
        "file_path": file_path,
        "example_sha256": example_sha256,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "min_scenarios": min_scenarios,
        "samples": samples
    }


def append_to_jsonl(record: Dict[str, Any], output_path: Path):
    """Append a record to the JSONL file.

    Args:
        record: Record to append
        output_path: Path to output file
    """
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)
    logger.info(f"Saved CWE-{record['cwe_id']} to {output_path}")


def load_processed_scenarios(output_path: Path) -> Set[tuple[str, str]]:
    """Load scenarios that have already been processed in the amplify command.

    Args:
        output_path: Path to the amplified output JSONL file

    Returns:
        Set of (rule, seed) tuples that are already in the output file
    """
    processed = set()

    if not output_path.exists():
        return processed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                if 'type' in record and 'seed' in record:
                    processed.add((record['type'], record['seed']))
        logger.info(f"Found {len(processed)} already-processed scenarios in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return processed


def load_processed_proposals(output_path: Path) -> Dict[str, Set[str]]:
    """Load proposals that have already been processed in the propose command.

    Args:
        output_path: Path to the propose output JSONL file

    Returns:
        Dict mapping vulnerability_type to set of completed goals ('nominal', 'failure')
    """
    from collections import defaultdict
    processed = defaultdict(set)

    if not output_path.exists():
        return dict(processed)

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                if 'type' in record and 'goal' in record:
                    processed[record['type']].add(record['goal'])

        total_count = sum(len(goals) for goals in processed.values())
        logger.info(f"Found {total_count} already-processed proposals in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return dict(processed)


def build_amplify_record(
    rule: str,
    seed: str,
    successes: List[tuple[str, Any]],
    failures: List[tuple[str, Any]],
    metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Build an amplify record for JSONL output.

    Args:
        rule: CodeQL rule ID (failure type)
        seed: Original scenario text
        successes: List of (prompt, FailureBeta) tuples from MCMC
        failures: List of (prompt, FailureBeta) tuples from MCMC
        metadata: Metadata dict with turns, beta_variance_threshold

    Returns:
        Dict representing the complete amplified record
    """
    successes_out = [
        {
            "prompt": prompt,
            "num_successes": beta.nominal_pseudocounts - 1,
            "num_failures": beta.failure_pseudocounts - 1
        }
        for prompt, beta in successes
    ]

    failures_out = [
        {
            "prompt": prompt,
            "num_successes": beta.nominal_pseudocounts - 1,
            "num_failures": beta.failure_pseudocounts - 1
        }
        for prompt, beta in failures
    ]

    return {
        "type": rule,
        "seed": seed,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "mcmc_successes": successes_out,
        "mcmc_failures": failures_out,
        "metadata": metadata
    }


def append_amplify_record(record: Dict[str, Any], output_path: Path):
    """Append an amplified record to the JSONL file.

    Args:
        record: Record to append
        output_path: Path to output file
    """
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


def build_propose_record(
    vulnerability_type: str,
    goal: str,
    prompt: str,
    quantify_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Build a propose record for JSONL output.

    Args:
        vulnerability_type: CodeQL rule ID
        goal: Either "nominal" or "failure"
        prompt: Generated prompt text
        quantify_result: Result from quantify() function

    Returns:
        Dict representing the complete propose record
    """
    return {
        "type": vulnerability_type,
        "goal": goal,
        "prompt": prompt,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "result": {
            "failure": quantify_result[0].failure_pseudocounts-1,
            "nominal": quantify_result[0].nominal_pseudocounts-1,
            "error_types": list(quantify_result[1])
        }
    }


def append_propose_record(record: Dict[str, Any], output_path: Path):
    """Append a propose record to the JSONL file.

    Args:
        record: Record to append
        output_path: Path to output file
    """
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


def load_completed_rollouts(output_path: Path) -> Set[str]:
    """Load rollout prompts that have already been processed.

    Args:
        output_path: Path to the rollout output JSONL file

    Returns:
        Set of prompt SHA256 hashes already processed
    """
    completed = set()

    if not output_path.exists():
        return completed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                prompt_hash = record.get("prompt_sha256")
                if prompt_hash:
                    completed.add(prompt_hash)
        logger.info(f"Found {len(completed)} already-completed rollouts in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing rollout output file: {e}")

    return completed


def build_rollout_record(
    prompt: str,
    pairs: List[tuple[str, str, Any]],
    k: int,
    max_rollouts: int
) -> Dict[str, Any]:
    """Build a rollout record for JSONL output."""
    prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    pairs_out = [
        {
            "success": success,
            "failure": failure,
            "failure_info": failure_info
        }
        for success, failure, failure_info in pairs
    ]

    return {
        "prompt": prompt,
        "prompt_sha256": prompt_sha256,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "k": k,
        "max_rollouts": max_rollouts,
        "pairs": pairs_out
    }


def append_rollout_record(record: Dict[str, Any], output_path: Path):
    """Append a rollout record to the JSONL file."""
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


def load_processed_patch_evaluations(output_path: Path) -> Set[tuple[str, str, str, str, str, str, bool]]:
    """Load patch evaluations that have already been processed.

    Args:
        output_path: Path to the patch evaluation output JSONL file

    Returns:
        Set of processed keys:
        (instance_id, model, repo, base, resolved, patch_sha256, skip_patch)
    """
    processed = set()

    if not output_path.exists():
        return processed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                required = {'instance_id', 'model', 'repo', 'base', 'resolved', 'patch_sha256'}
                if required.issubset(record.keys()):
                    processed.add((
                        str(record['instance_id']),
                        str(record['model']),
                        str(record['repo']),
                        str(record['base']),
                        str(record['resolved']),
                        str(record['patch_sha256']),
                        bool(record.get('skip_patch', False)),
                    ))
        logger.info(f"Found {len(processed)} already-processed patch evaluations in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return processed


def build_patch_evaluation_record(
    row: Dict[str, Any],
    patch_sha256: str,
    skip_patch: bool,
    evaluation: List[Dict[str, Any]] | None,
    error: str | None
) -> Dict[str, Any]:
    """Build a patch evaluation record for JSONL output."""
    return {
        "instance_id": row["instance_id"],
        "model": row["model"],
        "repo": row["repo"],
        "base": row["base"],
        "resolved": row["resolved"],
        "patch_sha256": patch_sha256,
        "skip_patch": skip_patch,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "evaluation": evaluation,
        "num_vulnerabilities": len(evaluation) if evaluation is not None else None,
        "error": error
    }


def append_patch_evaluation_record(record: Dict[str, Any], output_path: Path):
    """Append a patch evaluation record to the JSONL file."""
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


def process_scenario_worker(
    task_queue,
    write_queue,
    mcmc_steps: int,
    variance_threshold: float,
    model: str,
    api_key: str,
    api_base: str,
    temperature: float,
    log_level: int
):
    """Worker function that pulls tasks from queue and processes them.

    Args:
        task_queue: Queue to pull (scenario, rule) tasks from
        write_queue: Queue to write completed records to
        mcmc_steps: Number of MCMC turns
        variance_threshold: Beta variance threshold
        model: Model identifier
        api_key: API key
        api_base: API base URL
        temperature: Temperature for generation
        log_level: Logging level (e.g., logging.INFO, logging.DEBUG)
    """
    # Import here to avoid issues with multiprocessing
    from redcodegen.kernels import LMRephrasingKernel
    from redcodegen.uncertainty import mcmc
    from redcodegen.constants import create_lm

    # Set up logging for this worker process
    worker_logger = logging.getLogger("redcodegen")
    worker_logger.setLevel(log_level)
    worker_logger.addHandler(RichHandler(rich_tracebacks=True))

    # Each process needs its own DSPy configuration
    lm = create_lm(model_name=model, temperature=temperature, api_key=api_key, api_base=api_base)
    dspy.configure(lm=lm)

    worker_logger.debug("Worker started, waiting for tasks...")

    # Process tasks until we receive sentinel
    while True:
        task = task_queue.get()

        if task is None:  # Sentinel value to stop
            worker_logger.debug("Worker received stop signal")
            break

        scenario, rule = task
        seed = scenario["scenario"]

        worker_logger.debug(f"Processing scenario for {rule}: {seed[:50]}...")

        try:
            # Run MCMC for successes (find non-vulnerable prompts)
            worker_logger.debug(f"  Running MCMC for successes...")
            successes = mcmc(
                seed,
                LMRephrasingKernel(),
                turns=mcmc_steps,
                find_failure=False,
                threshold=variance_threshold,
                symmetric=True
            )[1:]  # crop seed

            # Run MCMC for failures (find vulnerable prompts)
            worker_logger.debug(f"  Running MCMC for failures...")
            failures_mcmc = mcmc(
                seed,
                LMRephrasingKernel(),
                turns=mcmc_steps,
                find_failure=True,
                threshold=variance_threshold,
                symmetric=True
            )[1:]  # crop seed

            # Build record
            record = build_amplify_record(
                rule=rule,
                seed=seed,
                successes=successes,
                failures=failures_mcmc,
                metadata={
                    "turns": mcmc_steps,
                    "beta_variance_threshold": variance_threshold
                }
            )

            # Write directly to queue
            write_queue.put(record)
            worker_logger.info(f"  ✓ Completed {rule} (successes: {len(successes)}, failures: {len(failures_mcmc)})")

        except Exception as e:
            worker_logger.error(f"  ✗ Failed to amplify scenario for {rule}: {e}")
            # Don't put anything in write queue on failure
            continue


def file_writer_worker(write_queue, output_path: Path, total_scenarios: int):
    """Long-running thread that consumes records from queue and writes to file.

    Args:
        write_queue: Queue containing records to write
        output_path: Path to output file
        total_scenarios: Total number of scenarios to process (for progress tracking)
    """
    counter = 0
    while True:
        record = write_queue.get()
        if record is None:  # Sentinel value to stop
            break
        try:
            append_amplify_record(record, output_path)
            counter += 1
            successes_count = len(record["mcmc_successes"])
            failures_count = len(record["mcmc_failures"])
            logger.info(
                f"[{counter}/{total_scenarios}] Wrote {record['type']} "
                f"(successes: {successes_count} chains, failures: {failures_count} chains)"
            )
        except Exception as e:
            logger.error(f"  ✗ Failed to write record: {e}")


@click.group()
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Enable verbose (DEBUG) logging'
)
def main(verbose):
    """RedCodegen - Generate and analyze vulnerable code samples."""
    # Set logging level based on verbose flag
    if verbose:
        redcodegen_logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")


@main.command()
@click.option(
    '--cwes', '-c',
    multiple=True,
    type=int,
    help='CWE IDs to process (can specify multiple times, e.g., -c 89 -c 79)'
)
@click.option(
    '--use-top-25',
    is_flag=True,
    help='Process all CWE Top 25'
)
@click.option(
    '--min-samples', '-n',
    default=3,
    type=int,
    help='Minimum samples per CWE (default: 3)'
)
@click.option(
    '--output', '-o',
    default='results.jsonl',
    type=click.Path(),
    help='Output JSONL file (default: results.jsonl)'
)
@click.option(
    '--model', '-m',
    default='openai/gpt-4o-mini',
    help='Model identifier (default: openai/gpt-4o-mini)'
)
@click.option(
    '--api-key',
    default=None,
    help='API key (defaults to OPENAI_API_KEY env var)'
)
@click.option(
    '--api-base',
    default=None,
    help='API base URL (defaults to OPENAI_API_BASE env var)'
)
@click.option(
    '--temperature',
    default=0.8,
    type=float,
    help='Temperature for code generation (default: 0.8)'
)
def generate(cwes, use_top_25, min_samples, output, model, api_key, api_base, temperature):
    """Generate benign prompts that could result in vulnerabilities exercising specified CWEs.

    Examples:
        redcodegen generate -c 89 -c 79 # manually specify cwe
        redcodegen generate -n 5 # specify number of rollouts
        redcodegen generate --use-top-25 # run CWE top 25
        redcodegen generate --use-top-25 -o results.jsonl # resume existing run
        redcodegen generate --use-top-25 --model openai/gpt-4o # switch model
    """
    # Configure DSPy with specified model
    lm = create_lm(model_name=model, temperature=temperature, api_key=api_key, api_base=api_base)
    dspy.configure(lm=lm)
    logger.info(f"Configured model: {model}")

    # Import generator and validator after configuring dspy
    from redcodegen.generator import run_cwe
    from redcodegen.validator import evaluate

    output_path = Path(output)

    # Determine which CWEs to process
    if use_top_25:
        cwes_to_process = CWE_TOP_25
        logger.info(f"Processing CWE Top 25 ({len(cwes_to_process)} CWEs)")
    elif cwes:
        cwes_to_process = list(cwes)
        logger.info(f"Processing {len(cwes_to_process)} specified CWEs")
    else:
        logger.error("Must specify either --cwes or --use-top-25")
        raise click.UsageError("Must specify either --cwes or --use-top-25")

    # Load already-completed CWEs for idempotency
    completed_cwes = load_completed_cwes(output_path)
    cwes_to_process = [cwe for cwe in cwes_to_process if cwe not in completed_cwes]

    if not cwes_to_process:
        logger.info("All CWEs already completed!")
        return

    logger.info(f"Processing {len(cwes_to_process)} CWEs (skipped {len(completed_cwes)} already completed)")

    # Initialize CWE database
    db = Database()

    # Process each CWE
    for idx, cwe_id in enumerate(cwes_to_process, 1):
        logger.info(f"[{idx}/{len(cwes_to_process)}] Processing CWE-{cwe_id}...")

        try:
            # Get CWE metadata
            entry = db.get(cwe_id)
            cwe_name = entry.name
            cwe_description = entry.extended_description or entry.description

            # Generate code samples
            logger.info(f"  Generating {min_samples} code samples...")
            codes = run_cwe(cwe_id, min_scenarios=min_samples)
            logger.info(f"  Generated {len(codes)} code samples")

            # Get scenarios (need to call generate again to get scenarios)
            from redcodegen.scenarios import generate
            scenario_data = generate(cwe_id, min_scenarios=min_samples)
            scenarios = scenario_data["scenarios"][:len(codes)]  # Match code count

            # Evaluate each code sample
            evaluations = []
            errors = []

            for i, code in enumerate(codes, 1):
                logger.info(f"  Evaluating sample {i}/{len(codes)}...")
                try:
                    evaluation = evaluate(code)
                    evaluations.append(evaluation)
                    errors.append(None)
                    logger.info(f"    Found {len(evaluation)} vulnerabilities")
                except Exception as e:
                    logger.warning(f"    Evaluation failed: {e}")
                    evaluations.append(None)
                    errors.append(str(e))

            # Build and save record
            record = build_record(
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                cwe_description=cwe_description,
                scenarios=scenarios,
                codes=codes,
                evaluations=evaluations,
                errors=errors,
                min_scenarios=min_samples
            )

            append_to_jsonl(record, output_path)
            logger.info(f"✓ Completed CWE-{cwe_id}")

        except Exception as e:
            logger.error(f"✗ Failed to process CWE-{cwe_id}: {e}")
            continue

    logger.info(f"Completed! Results saved to {output_path}")


@main.command(name="regenerate")
@click.option(
    '--dir', '-d',
    required=False,
    type=click.Path(exists=True, file_okay=False),
    help='Input directory containing example files to regenerate'
)
@click.option(
    '--patches',
    required=False,
    type=click.Path(exists=True, dir_okay=False),
    help='Input JSONL file with patch records (same format as evaluate)'
)
@click.option(
    '--min-samples', '-n',
    default=3,
    type=int,
    help='Minimum samples per example (default: 3)'
)
@click.option(
    '--output', '-o',
    default='regenerate_results.jsonl',
    type=click.Path(),
    help='Output JSONL file (default: regenerate_results.jsonl)'
)
@click.option(
    '--model', '-m',
    default='openai/gpt-4o-mini',
    help='Model identifier (default: openai/gpt-4o-mini)'
)
@click.option(
    '--api-key',
    default=None,
    help='API key (defaults to OPENAI_API_KEY env var)'
)
@click.option(
    '--api-base',
    default=None,
    help='API base URL (defaults to OPENAI_API_BASE env var)'
)
@click.option(
    '--temperature',
    default=0.8,
    type=float,
    help='Temperature for code generation (default: 0.8)'
)
def regenerate_examples(dir, patches, min_samples, output, model, api_key, api_base, temperature):
    """Regenerate code examples from a directory of example files or patch records."""
    # Configure DSPy with specified model
    lm = create_lm(model_name=model, temperature=temperature, api_key=api_key, api_base=api_base)
    dspy.configure(lm=lm)
    logger.info(f"Configured model: {model}")

    # Import generator and validator after configuring dspy
    from redcodegen.generator import run_example
    from redcodegen.validator import evaluate

    output_path = Path(output)

    if bool(dir) == bool(patches):
        logger.error("Must specify exactly one of --dir or --patches")
        raise click.UsageError("Must specify exactly one of --dir or --patches")

    if patches:
        from redcodegen.patch import patched_changed_files

        input_path = Path(patches)
        logger.info(f"Loading patch records from {input_path}")
        try:
            with jsonlines.open(input_path) as reader:
                rows = [row for row in reader]
        except Exception as e:
            logger.error(f"Failed to read input file: {e}")
            raise click.Abort()

        if not rows:
            logger.warning("No records found in input file")
            return

        required_keys = {"instance_id", "model", "repo", "base", "patch", "resolved"}
        processed = load_completed_patch_regenerations(output_path)

        valid_rows = []
        skipped_invalid = 0
        skipped_completed = 0
        for idx, row in enumerate(rows, 1):
            missing = sorted(required_keys - set(row.keys()))
            if missing:
                skipped_invalid += 1
                logger.error(f"Skipping row {idx}: missing required keys {missing}")
                continue

            patch_text = row["patch"] if isinstance(row["patch"], str) else str(row["patch"])
            patch_sha256 = hashlib.sha256(patch_text.encode('utf-8')).hexdigest()
            valid_rows.append((row, patch_text, patch_sha256))

        if not valid_rows:
            logger.warning("No valid patch rows to process")
            return

        for row_idx, (row, patch_text, patch_sha256) in enumerate(valid_rows, 1):
            logger.info(
                f"[{row_idx}/{len(valid_rows)}] Processing patch "
                f"{row.get('instance_id')} ({patch_sha256[:8]})..."
            )

            try:
                changed_files = patched_changed_files(
                    repo=row["repo"],
                    commit=row["base"],
                    patch=patch_text
                )
            except Exception as e:
                logger.error(f"✗ Failed to apply patch for instance {row.get('instance_id')}: {e}")
                continue

            if not changed_files:
                logger.warning("  No changed files found after applying patch")
                continue

            for file_path, content in changed_files:
                file_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                key = (patch_sha256, file_path, file_hash)
                if key in processed:
                    skipped_completed += 1
                    continue

                logger.info(f"  Processing changed file {file_path}...")
                try:
                    logger.info(f"    Generating {min_samples} code samples...")
                    scenarios, codes = run_example(str=content, min_scenarios=min_samples)
                    logger.info(f"    Generated {len(codes)} code samples")

                    scenarios = scenarios[:len(codes)]

                    evaluations = []
                    for i, code in enumerate(codes, 1):
                        logger.info(f"    Evaluating sample {i}/{len(codes)}...")
                        try:
                            evaluation = evaluate(code)
                            evaluations.append(evaluation)
                            logger.info(f"      Found {len(evaluation)} vulnerabilities")
                        except Exception as e:
                            logger.warning(f"      Evaluation failed: {e}")
                            evaluations.append(None)

                    record = build_patch_regenerate_record(
                        instance_id=str(row["instance_id"]),
                        model=str(row["model"]),
                        repo=str(row["repo"]),
                        base=str(row["base"]),
                        resolved=str(row["resolved"]),
                        patch_sha256=patch_sha256,
                        file_path=str(file_path),
                        example_sha256=file_hash,
                        scenarios=scenarios,
                        codes=codes,
                        evaluations=evaluations,
                        min_scenarios=min_samples
                    )

                    append_to_jsonl(record, output_path)
                    processed.add(key)
                    logger.info(f"  ✓ Completed {file_path}")

                except Exception as e:
                    logger.error(f"  ✗ Failed to process {file_path}: {e}")
                    continue

        if skipped_invalid:
            logger.info(f"Skipped {skipped_invalid} invalid rows")
        if skipped_completed:
            logger.info(f"Skipped {skipped_completed} already-completed files")

        logger.info(f"Completed! Results saved to {output_path}")
        return

    input_path = Path(dir)
    all_files = sorted([p for p in input_path.rglob("*") if p.is_file()], key=lambda p: str(p))
    if not all_files:
        logger.warning(f"No files found under {input_path}")
        return

    completed_hashes = load_completed_examples(output_path)

    files_to_process = []
    skipped_completed = 0
    skipped_unreadable = 0
    for file_path in all_files:
        try:
            content = file_path.read_bytes()
        except Exception as e:
            skipped_unreadable += 1
            logger.warning(f"Skipping unreadable file {file_path}: {e}")
            continue

        file_hash = hashlib.sha256(content).hexdigest()
        if file_hash in completed_hashes:
            skipped_completed += 1
            continue

        rel_path = str(file_path.relative_to(input_path))
        files_to_process.append((file_path, rel_path, file_hash))

    if not files_to_process:
        logger.info("All example files already completed!")
        return

    logger.info(
        f"Processing {len(files_to_process)} examples "
        f"(skipped {skipped_completed} already completed, {skipped_unreadable} unreadable)"
    )

    for idx, (file_path, rel_path, file_hash) in enumerate(files_to_process, 1):
        logger.info(f"[{idx}/{len(files_to_process)}] Processing {rel_path}...")

        try:
            logger.info(f"  Generating {min_samples} code samples...")
            scenarios, codes = run_example(path=str(file_path), min_scenarios=min_samples)
            logger.info(f"  Generated {len(codes)} code samples")

            scenarios = scenarios[:len(codes)]

            evaluations = []
            for i, code in enumerate(codes, 1):
                logger.info(f"  Evaluating sample {i}/{len(codes)}...")
                try:
                    evaluation = evaluate(code)
                    evaluations.append(evaluation)
                    logger.info(f"    Found {len(evaluation)} vulnerabilities")
                except Exception as e:
                    logger.warning(f"    Evaluation failed: {e}")
                    evaluations.append(None)

            record = build_example_record(
                example_path=rel_path,
                example_sha256=file_hash,
                scenarios=scenarios,
                codes=codes,
                evaluations=evaluations,
                min_scenarios=min_samples
            )

            append_to_jsonl(record, output_path)
            logger.info(f"✓ Completed {rel_path}")

        except Exception as e:
            logger.error(f"✗ Failed to process {rel_path}: {e}")
            continue

    logger.info(f"Completed! Results saved to {output_path}")


@main.command()
@click.option(
    '--input', '-i',
    required=True,
    type=click.Path(exists=True),
    help='Input JSONL file with patch records to evaluate'
)
@click.option(
    '--output', '-o',
    default='patch_evaluations.jsonl',
    type=click.Path(),
    help='Output JSONL file for patch evaluation results (default: patch_evaluations.jsonl)'
)
@click.option(
    '--workdir',
    default='/tmp',
    type=click.Path(),
    help='Working directory for temporary CodeQL files (default: /tmp)'
)
@click.option(
    '--skip-patch',
    is_flag=True,
    help='Skip applying patch; evaluate repository at base commit only'
)
def evaluate(input, output, workdir, skip_patch):
    """Evaluate patched repositories with CodeQL static analysis.

    Input JSONL rows must contain:
        instance_id, model, repo, base, patch, resolved

    Examples:
        redcodegen evaluate -i swebench_patches.jsonl
        redcodegen evaluate -i swebench_patches.jsonl -o swebench_eval.jsonl
        redcodegen evaluate -i swebench_patches.jsonl --workdir /tmp
        redcodegen evaluate -i swebench_patches.jsonl --skip-patch
    """
    from redcodegen.patch import patched_evaluate

    input_path = Path(input)
    output_path = Path(output)
    workdir_path = Path(workdir)

    logger.info(f"Loading patch records from {input_path}")
    try:
        with jsonlines.open(input_path) as reader:
            rows = [row for row in reader]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        raise click.Abort()

    if not rows:
        logger.warning("No records found in input file")
        return

    logger.info(f"Loaded {len(rows)} records from input")
    if skip_patch:
        logger.info("Patch application is disabled (--skip-patch); evaluating base commits only")

    required_keys = {"instance_id", "model", "repo", "base", "patch", "resolved"}
    processed = load_processed_patch_evaluations(output_path)

    valid_rows = []
    skipped_invalid = 0
    skipped_completed = 0
    for idx, row in enumerate(rows, 1):
        missing = sorted(required_keys - set(row.keys()))
        if missing:
            skipped_invalid += 1
            logger.error(f"Skipping row {idx}: missing required keys {missing}")
            continue

        patch_text = row["patch"] if isinstance(row["patch"], str) else str(row["patch"])
        patch_sha256 = hashlib.sha256(patch_text.encode('utf-8')).hexdigest()
        row_key = (
            str(row["instance_id"]),
            str(row["model"]),
            str(row["repo"]),
            str(row["base"]),
            str(row["resolved"]),
            patch_sha256,
            bool(skip_patch)
        )
        if row_key in processed:
            skipped_completed += 1
            continue
        valid_rows.append((row, patch_text, patch_sha256))

    if skipped_invalid > 0:
        logger.warning(f"Skipped {skipped_invalid} invalid rows")
    if skipped_completed > 0:
        logger.info(f"Skipped {skipped_completed} already completed rows from output")

    if not valid_rows:
        logger.info("All patch evaluations already completed!")
        return

    logger.info(f"Processing {len(valid_rows)} rows (skipped {skipped_completed} already completed)")

    success_count = 0
    failure_count = 0
    evaluation_cache = {}
    for idx, (row, patch_text, patch_sha256) in enumerate(valid_rows, 1):
        instance_id = row["instance_id"]
        model = row["model"]
        repo = row["repo"]
        base = row["base"]

        logger.info(f"[{idx}/{len(valid_rows)}] Evaluating {instance_id} ({model})")
        logger.debug(f"  Repo: {repo} @ {base}")

        cache_key = (
            str(repo),
            str(base),
            "__SKIP_PATCH__" if skip_patch else patch_sha256,
            bool(skip_patch),
        )

        if cache_key in evaluation_cache:
            evaluation_result, error = evaluation_cache[cache_key]
            logger.debug("  Reusing cached evaluation result")
        else:
            try:
                evaluation_result = patched_evaluate(
                    repo=repo,
                    commit=base,
                    patch=patch_text,
                    workdir=str(workdir_path),
                    skip_patch=skip_patch
                )
                error = None
            except Exception as e:
                evaluation_result = None
                error = str(e)
            evaluation_cache[cache_key] = (evaluation_result, error)

        if error is None:
            success_count += 1
            logger.info(f"  ✓ Found {len(evaluation_result)} vulnerabilities")
        else:
            failure_count += 1
            logger.error(f"  ✗ Failed to evaluate {instance_id} ({model}): {error}")

        record = build_patch_evaluation_record(
            row=row,
            patch_sha256=patch_sha256,
            skip_patch=skip_patch,
            evaluation=evaluation_result,
            error=error
        )
        append_patch_evaluation_record(record, output_path)

    logger.info(
        f"Completed! Processed {len(valid_rows)} rows "
        f"(successes: {success_count}, failures: {failure_count}) saved to {output_path}"
    )


@main.command()
@click.option(
    '--input', '-i',
    required=True,
    type=click.Path(exists=True),
    help='Input JSONL file from generate command'
)
@click.option(
    '--output', '-o',
    required=True,
    type=click.Path(),
    help='Output JSONL file for amplified results'
)
@click.option(
    '--mcmc-steps',
    default=16,
    type=int,
    help='Number of MCMC turns (default: 16)'
)
@click.option(
    '--variance-threshold',
    default=0.015,
    type=float,
    help='Beta variance threshold for stopping (default: 0.015)'
)
@click.option(
    '--workers', '-w',
    default=None,
    type=int,
    help='Number of parallel workers (default: CPU count)'
)
@click.option(
    '--filter-rule', '-r',
    multiple=True,
    help='Specific CodeQL rule(s) to process (can specify multiple times)'
)
@click.option(
    '--ignore-rule', '-x',
    multiple=True,
    help='CodeQL rule(s) to ignore/exclude (can specify multiple times)'
)
@click.option(
    '--model', '-m',
    default='openai/gpt-4o-mini',
    help='Model identifier (default: openai/gpt-4o-mini)'
)
@click.option(
    '--api-key',
    default=None,
    help='API key (defaults to OPENAI_API_KEY env var)'
)
@click.option(
    '--api-base',
    default=None,
    help='API base URL (defaults to OPENAI_API_BASE env var)'
)
@click.option(
    '--temperature',
    default=0.8,
    type=float,
    help='Temperature for rephrasing (default: 0.8)'
)
def amplify(input, output, mcmc_steps, variance_threshold, workers, filter_rule, ignore_rule, model, api_key, api_base, temperature):
    """Amplify vulnerable scenarios using MCMC to explore failure boundaries.

    Takes output from 'generate' command and runs MCMC to find nearby prompts
    that both succeed (safe code) and fail (vulnerable code).

    Examples:
        redcodegen amplify -i results.jsonl -o amplified.jsonl
        redcodegen amplify -i results.jsonl -o amplified.jsonl --mcmc-steps 32
        redcodegen amplify -i results.jsonl -o amplified.jsonl -r py/sql-injection
        redcodegen amplify -i results.jsonl -o amplified.jsonl -x py/path-injection
        redcodegen amplify -i results.jsonl -o amplified.jsonl # resume partial run
        redcodegen amplify -i results.jsonl -o amplified.jsonl --model openai/gpt-4o
    """
    # Configure DSPy with specified model
    lm = create_lm(model_name=model, temperature=temperature, api_key=api_key, api_base=api_base)
    dspy.configure(lm=lm)
    logger.info(f"Configured model: {model}")

    from collections import defaultdict
    from redcodegen.kernels import LMRephrasingKernel
    from redcodegen.uncertainty import mcmc

    input_path = Path(input)
    output_path = Path(output)

    # Load input data
    logger.info(f"Loading input from {input_path}")
    try:
        with jsonlines.open(input_path) as reader:
            data = [record for record in reader]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        raise click.Abort()

    logger.info(f"Loaded {len(data)} records from input")

    # Extract all samples and filter to vulnerable ones
    all_samples = sum([record["samples"] for record in data], [])
    vulnerable_samples = [sample for sample in all_samples if sample.get("evaluation") and len(sample["evaluation"]) > 0]

    if not vulnerable_samples:
        logger.warning("No vulnerable samples found in input file")
        return

    logger.info(f"Found {len(vulnerable_samples)} vulnerable samples")

    # Group by failure type (first evaluation rule)
    failures = defaultdict(list)
    for sample in vulnerable_samples:
        rule = sample["evaluation"][0]["rule"]
        failures[rule].append(sample)
    failures = dict(failures)

    logger.info(f"Grouped into {len(failures)} failure types: {list(failures.keys())}")

    # Apply filter if specified
    if filter_rule:
        filtered_failures = {rule: samples for rule, samples in failures.items() if rule in filter_rule}
        if not filtered_failures:
            logger.warning(f"No samples match filter rules: {filter_rule}")
            return
        failures = filtered_failures
        logger.info(f"Filtered to {len(failures)} failure types: {list(failures.keys())}")

    # Apply ignore filter if specified
    if ignore_rule:
        filtered_failures = {rule: samples for rule, samples in failures.items() if rule not in ignore_rule}
        if not filtered_failures:
            logger.warning(f"All samples were excluded by ignore rules: {ignore_rule}")
            return
        excluded_count = len(failures) - len(filtered_failures)
        failures = filtered_failures
        logger.info(f"Excluded {excluded_count} failure types, processing {len(failures)} failure types: {list(failures.keys())}")

    # Load already-processed scenarios for idempotency
    processed_scenarios = load_processed_scenarios(output_path)
    if processed_scenarios:
        logger.info(f"Resuming from existing output, will skip {len(processed_scenarios)} already-processed scenarios")

    # Set up parallelization
    n_workers = workers if workers is not None else os.cpu_count()
    logger.info(f"Using {n_workers} parallel workers")

    # Create manager and queues
    manager = Manager()
    task_queue = manager.Queue()
    write_queue = manager.Queue()

    # Count total scenarios to process
    all_tasks = []
    for rule, samples in failures.items():
        for scenario in samples:
            if (rule, scenario["scenario"]) not in processed_scenarios:
                all_tasks.append((scenario, rule))

    total_scenarios = len(all_tasks)
    logger.info(f"Total scenarios to process: {total_scenarios}")

    if total_scenarios == 0:
        logger.info("All scenarios already processed!")
        return

    # Start file writer thread
    writer_thread = Thread(target=file_writer_worker, args=(write_queue, output_path, total_scenarios))
    writer_thread.start()
    logger.debug("Started file writer thread")

    try:
        # Populate task queue
        logger.debug(f"Populating task queue with {total_scenarios} tasks...")
        for task in all_tasks:
            task_queue.put(task)

        # Add sentinel values for workers to stop
        for _ in range(n_workers):
            task_queue.put(None)

        logger.debug("Task queue populated")

        # Start worker processes
        current_log_level = redcodegen_logger.level
        with Pool(processes=n_workers) as pool:
            # Start all workers
            worker_args = (
                task_queue,
                write_queue,
                mcmc_steps,
                variance_threshold,
                model,
                api_key,
                api_base,
                temperature,
                current_log_level
            )

            # Use apply_async to start workers that will process tasks from queue
            results = [pool.apply_async(process_scenario_worker, worker_args) for _ in range(n_workers)]

            # Wait for all workers to complete
            for result in results:
                result.get()

        logger.info("All workers finished")

    finally:
        # Signal writer thread to stop and wait for it
        logger.debug("Sending shutdown signal to writer thread")
        write_queue.put(None)
        writer_thread.join()
        logger.debug("Writer thread finished")

    logger.info(f"Completed! Processed {total_scenarios} scenarios saved to {output_path}")


@main.command()
@click.option(
    '--output', '-o',
    required=True,
    type=click.Path(),
    help='Output JSONL file for proposed prompts'
)
@click.option(
    '--base-model', '-b',
    required=True,
    help='Base model for ProposalDistribution (e.g., Qwen/Qwen2.5-0.5B-Instruct)'
)
@click.option(
    '--peft', '-p',
    default=None,
    type=click.Path(exists=True),
    help='Optional PEFT adapter path'
)
@click.option(
    '--num-samples', '-n',
    default=10,
    type=int,
    help='Number of samples per vulnerability type (default: 10)'
)
@click.option(
    '--variance-threshold',
    default=0.015,
    type=float,
    help='Beta variance threshold for quantify (default: 0.015)'
)
@click.option(
    '--min-rollouts',
    default=2,
    type=int,
    help='Minimum rollouts for quantify (default: 2)'
)
@click.option(
    '--vulnerabilities', '-v',
    multiple=True,
    help='Specific CodeQL rule(s) to test (can specify multiple times)'
)
@click.option(
    '--vulnerabilities-file', '-f',
    type=click.Path(exists=True),
    help='File containing CodeQL rules to test (one per line)'
)
@click.option(
    '--model', '-m',
    default='openai/gpt-4o-mini',
    help='Model identifier for code generation (default: openai/gpt-4o-mini)'
)
@click.option(
    '--api-key',
    default=None,
    help='API key (defaults to OPENAI_API_KEY env var)'
)
@click.option(
    '--api-base',
    default=None,
    help='API base URL (defaults to OPENAI_API_BASE env var)'
)
@click.option(
    '--temperature',
    default=0.8,
    type=float,
    help='Temperature for code generation (default: 0.8)'
)
def propose(output, base_model, peft, num_samples, variance_threshold, min_rollouts,
            vulnerabilities, vulnerabilities_file, model, api_key, api_base, temperature):
    """Generate and evaluate coding task prompts using a fine-tuned proposal model.

    This command uses a ProposalDistribution (base model + optional PEFT) to generate
    prompts that either will or will not cause specific vulnerability types, then
    evaluates their reliability through multiple code generation rollouts.

    Examples:
        redcodegen propose -o proposals.jsonl -b Qwen/Qwen2.5-0.5B-Instruct -v py/sql-injection
        redcodegen propose -o proposals.jsonl -b Qwen/... -p /path/to/peft -v py/xss
        redcodegen propose -o proposals.jsonl -b Qwen/... -v py/sql-injection -v py/xss
        redcodegen propose -o proposals.jsonl -b Qwen/... -f vulnerabilities.txt
        redcodegen propose -o proposals.jsonl -b Qwen/... -f vulns.txt -v py/extra-vuln
    """
    # Configure DSPy with specified model for code generation
    lm = create_lm(model_name=model, temperature=temperature, api_key=api_key, api_base=api_base)
    dspy.configure(lm=lm)
    logger.info(f"Configured code generation model: {model}")

    output_path = Path(output)

    # Initialize ProposalDistribution
    logger.info(f"Initializing ProposalDistribution with base model: {base_model}")
    if peft:
        logger.info(f"Using PEFT adapter: {peft}")

    try:
        proposal_dist = ProposalDistribution(base=base_model, peft=peft)
    except Exception as e:
        logger.error(f"Failed to initialize ProposalDistribution: {e}")
        raise click.Abort()

    # Determine which vulnerabilities to test
    vulns_to_test = []

    # Add vulnerabilities from -v flag
    if vulnerabilities:
        vulns_to_test.extend(vulnerabilities)
        logger.info(f"Added {len(vulnerabilities)} vulnerabilities from --vulnerabilities flag")

    # Add vulnerabilities from file
    if vulnerabilities_file:
        logger.info(f"Reading vulnerabilities from file: {vulnerabilities_file}")
        try:
            with open(vulnerabilities_file, 'r') as f:
                file_vulns = [line.strip() for line in f if line.strip()]
            vulns_to_test.extend(file_vulns)
            logger.info(f"Added {len(file_vulns)} vulnerabilities from file")
        except Exception as e:
            logger.error(f"Failed to read vulnerabilities file: {e}")
            raise click.Abort()

    # Check if we have any vulnerabilities
    if not vulns_to_test:
        logger.error("Must specify at least one vulnerability with --vulnerabilities/-v or --vulnerabilities-file/-f")
        raise click.UsageError("Must specify at least one vulnerability with --vulnerabilities/-v or --vulnerabilities-file/-f")

    # Remove duplicates while preserving order
    seen = set()
    vulns_to_test = [v for v in vulns_to_test if not (v in seen or seen.add(v))]

    logger.info(f"Testing {len(vulns_to_test)} total vulnerabilities: {vulns_to_test}")

    # Load already-processed proposals for idempotency
    processed_proposals = load_processed_proposals(output_path)

    # Calculate how many tasks remain per vulnerability
    remaining_tasks = []
    for vuln_type in vulns_to_test:
        completed_goals = processed_proposals.get(vuln_type, set())
        nominal_count = len([g for g in completed_goals if g == 'nominal'])
        failure_count = len([g for g in completed_goals if g == 'failure'])

        remaining_nominal = max(0, num_samples - nominal_count)
        remaining_failure = max(0, num_samples - failure_count)

        remaining_tasks.append((vuln_type, remaining_nominal, remaining_failure))

    total_remaining = sum(n + f for _, n, f in remaining_tasks)
    total_possible = len(vulns_to_test) * num_samples * 2
    skipped = total_possible - total_remaining

    if skipped > 0:
        logger.info(f"Resuming from existing output: {skipped} tasks already completed, {total_remaining} remaining")

    if total_remaining == 0:
        logger.info("All proposals already completed!")
        return

    # Process each vulnerability type
    task_counter = 0

    for vuln_idx, (vuln_type, remaining_nominal, remaining_failure) in enumerate(remaining_tasks, 1):
        if remaining_nominal == 0 and remaining_failure == 0:
            logger.info(f"[{vuln_idx}/{len(vulns_to_test)}] Skipping {vuln_type} (already completed)")
            continue

        logger.info(f"[{vuln_idx}/{len(vulns_to_test)}] Processing {vuln_type} (nominal: {remaining_nominal}, failure: {remaining_failure})")

        completed_goals = processed_proposals.get(vuln_type, set())
        nominal_samples_done = len([g for g in completed_goals if g == 'nominal'])
        failure_samples_done = len([g for g in completed_goals if g == 'failure'])

        for sample_idx in range(1, num_samples + 1):
            # Generate NOMINAL prompt (should NOT cause vulnerability)
            if sample_idx > nominal_samples_done:
                task_counter += 1
                logger.info(f"  [{task_counter}/{total_remaining}] Generating NOMINAL prompt {sample_idx}/{num_samples}")

                try:
                    request = GenerateRequest(failure_type=vuln_type, goal=Goal.NOMINAL)
                    nominal_prompt = proposal_dist.generate(request)
                    logger.debug(f"    Prompt: {nominal_prompt[:100]}...")

                    # Quantify the nominal prompt
                    logger.debug(f"    Quantifying with threshold={variance_threshold}, min_rollouts={min_rollouts}")
                    nominal_result = quantify(
                        nominal_prompt,
                        threshold=variance_threshold,
                        min_rollouts=min_rollouts,
                        return_evaluations=True
                    )

                    # Build and save record
                    record = build_propose_record(
                        vulnerability_type=vuln_type,
                        goal="nominal",
                        prompt=nominal_prompt,
                        quantify_result=nominal_result
                    )
                    append_propose_record(record, output_path)

                    failure_count = nominal_result[0].failure_pseudocounts-1
                    nominal_count = nominal_result[0].nominal_pseudocounts-1
                    logger.info(f"    ✓ NOMINAL prompt: {failure_count} failures, {nominal_count} successes")

                except Exception as e:
                    logger.error(f"    ✗ Failed to generate/quantify NOMINAL prompt: {e}")
                    continue

            # Generate FAILURE prompt (SHOULD cause vulnerability)
            if sample_idx > failure_samples_done:
                task_counter += 1
                logger.info(f"  [{task_counter}/{total_remaining}] Generating FAILURE prompt {sample_idx}/{num_samples}")

                try:
                    request = GenerateRequest(failure_type=vuln_type, goal=Goal.FAILURE)
                    failure_prompt = proposal_dist.generate(request)
                    logger.debug(f"    Prompt: {failure_prompt[:100]}...")

                    # Quantify the failure prompt
                    logger.debug(f"    Quantifying with threshold={variance_threshold}, min_rollouts={min_rollouts}")
                    failure_result = quantify(
                        failure_prompt,
                        threshold=variance_threshold,
                        min_rollouts=min_rollouts,
                        return_evaluations=True
                    )

                    # Build and save record
                    record = build_propose_record(
                        vulnerability_type=vuln_type,
                        goal="failure",
                        prompt=failure_prompt,
                        quantify_result=failure_result
                    )
                    append_propose_record(record, output_path)

                    failure_count = failure_result[0].failure_pseudocounts-1
                    nominal_count = failure_result[0].nominal_pseudocounts-1
                    logger.info(f"    ✓ FAILURE prompt: {failure_count} failures, {nominal_count} successes")

                except Exception as e:
                    logger.error(f"    ✗ Failed to generate/quantify FAILURE prompt: {e}")
                    continue

        logger.info(f"  ✓ Completed {vuln_type}")

    logger.info(f"Completed! Processed {task_counter} tasks, results saved to {output_path}")


@main.command()
@click.option(
    '--input', '-i',
    required=True,
    type=click.Path(exists=True),
    help='Input JSONL file from amplify command'
)
@click.option(
    '--output', '-o',
    required=True,
    type=click.Path(),
    help='Output JSONL file for rollout pairs'
)
@click.option(
    '--k',
    default=5,
    type=int,
    help='Number of success/failure pairs to collect per prompt (default: 5)'
)
@click.option(
    '--max-rollouts',
    default=20,
    type=int,
    help='Maximum rollouts to attempt per prompt (default: 20)'
)
@click.option(
    '--model', '-m',
    default='openai/gpt-4o-mini',
    help='Model identifier for code generation (default: openai/gpt-4o-mini)'
)
@click.option(
    '--api-key',
    default=None,
    help='API key (defaults to OPENAI_API_KEY env var)'
)
@click.option(
    '--api-base',
    default=None,
    help='API base URL (defaults to OPENAI_API_BASE env var)'
)
@click.option(
    '--temperature',
    default=0.8,
    type=float,
    help='Temperature for code generation (default: 0.8)'
)
def rollout(input, output, k, max_rollouts, model, api_key, api_base, temperature):
    """Roll out amplified failure prompts to produce paired success/failure generations."""
    # Configure DSPy with specified model
    lm = create_lm(model_name=model, temperature=temperature, api_key=api_key, api_base=api_base)
    dspy.configure(lm=lm)
    logger.info(f"Configured code generation model: {model}")

    from redcodegen.contrastive import rollout_k_pairs

    input_path = Path(input)
    output_path = Path(output)

    # Load amplify data
    logger.info(f"Loading amplified data from {input_path}")
    try:
        with jsonlines.open(input_path) as reader:
            data = [record for record in reader]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        raise click.Abort()

    if not data:
        logger.warning("No records found in input file")
        return

    # Extract prompts from mcmc_failures
    prompts = []
    for record in data:
        failures = record.get("mcmc_failures", [])
        for failure in failures:
            prompt = failure.get("prompt")
            if prompt:
                prompts.append(prompt)

    if not prompts:
        logger.warning("No failure prompts found in input file")
        return

    # Deduplicate prompts while preserving order
    seen_prompts = set()
    unique_prompts = []
    for prompt in prompts:
        if prompt not in seen_prompts:
            seen_prompts.add(prompt)
            unique_prompts.append(prompt)

    # Load already-processed prompt hashes for idempotency
    completed_hashes = load_completed_rollouts(output_path)

    logger.info(
        f"Prepared {len(unique_prompts)} unique prompts "
        f"(skipping {len(completed_hashes)} already completed)"
    )

    processed = 0
    skipped = 0
    for idx, prompt in enumerate(unique_prompts, 1):
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        if prompt_hash in completed_hashes:
            skipped += 1
            continue

        logger.info(f"[{idx}/{len(unique_prompts)}] Rolling out prompt...")
        try:
            pairs = rollout_k_pairs(prompt, k=k, max_rollouts=max_rollouts)
            record = build_rollout_record(
                prompt=prompt,
                pairs=pairs,
                k=k,
                max_rollouts=max_rollouts
            )
            append_rollout_record(record, output_path)
            completed_hashes.add(prompt_hash)
            processed += 1
            logger.info(f"  ✓ Saved {len(pairs)} pairs (requested k={k})")
        except Exception as e:
            logger.error(f"  ✗ Failed to roll out prompt: {e}")
            continue

    logger.info(
        f"Completed rollout. Saved {processed} prompts "
        f"(skipped {skipped} already completed) to {output_path}"
    )


if __name__ == '__main__':
    main()

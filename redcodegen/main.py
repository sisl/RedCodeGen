"""
main.py
Main script for generating and evaluating vulnerable code samples
"""

import rich_click as click
import jsonlines
import logging
import dspy
import os
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
        "result": quantify_result
    }


def append_propose_record(record: Dict[str, Any], output_path: Path):
    """Append a propose record to the JSONL file.

    Args:
        record: Record to append
        output_path: Path to output file
    """
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
            vulnerabilities, model, api_key, api_base, temperature):
    """Generate and evaluate coding task prompts using a fine-tuned proposal model.

    This command uses a ProposalDistribution (base model + optional PEFT) to generate
    prompts that either will or will not cause specific vulnerability types, then
    evaluates their reliability through multiple code generation rollouts.

    Examples:
        redcodegen propose -o proposals.jsonl -b Qwen/Qwen2.5-0.5B-Instruct
        redcodegen propose -o proposals.jsonl -b Qwen/... -p /path/to/peft
        redcodegen propose -o proposals.jsonl -b Qwen/... -v py/sql-injection -v py/xss
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
        proposal_dist = ProposalDistribution(base_model=base_model, peft=peft)
    except Exception as e:
        logger.error(f"Failed to initialize ProposalDistribution: {e}")
        raise click.Abort()

    # Determine which vulnerabilities to test
    if vulnerabilities:
        vulns_to_test = list(vulnerabilities)
        logger.info(f"Testing {len(vulns_to_test)} specified vulnerabilities: {vulns_to_test}")
    else:
        # Default to some common vulnerabilities or empty list
        logger.error("Must specify at least one vulnerability with --vulnerabilities/-v")
        raise click.UsageError("Must specify at least one vulnerability with --vulnerabilities/-v")

    # Process each vulnerability type
    total_tasks = len(vulns_to_test) * num_samples * 2  # 2 = nominal + failure
    task_counter = 0

    logger.info(f"Starting proposal generation: {len(vulns_to_test)} vulnerabilities × {num_samples} samples × 2 goals = {total_tasks} total tasks")

    for vuln_idx, vuln_type in enumerate(vulns_to_test, 1):
        logger.info(f"[{vuln_idx}/{len(vulns_to_test)}] Processing vulnerability: {vuln_type}")

        for sample_idx in range(1, num_samples + 1):
            # Generate NOMINAL prompt (should NOT cause vulnerability)
            task_counter += 1
            logger.info(f"  [{task_counter}/{total_tasks}] Generating NOMINAL prompt {sample_idx}/{num_samples}")

            try:
                request = GenerateRequest(type=vuln_type, goal=Goal.NOMINAL)
                nominal_prompt = proposal_dist(request)
                logger.debug(f"    Prompt: {nominal_prompt[:100]}...")

                # Quantify the nominal prompt
                logger.debug(f"    Quantifying with threshold={variance_threshold}, min_rollouts={min_rollouts}")
                nominal_result = quantify(
                    nominal_prompt,
                    threshold=variance_threshold,
                    min_rollouts=min_rollouts
                )

                # Build and save record
                record = build_propose_record(
                    vulnerability_type=vuln_type,
                    goal="nominal",
                    prompt=nominal_prompt,
                    quantify_result=nominal_result
                )
                append_propose_record(record, output_path)

                failure_count = nominal_result.get("failure", 0)
                nominal_count = nominal_result.get("nominal", 0)
                logger.info(f"    ✓ NOMINAL prompt: {failure_count} failures, {nominal_count} successes")

            except Exception as e:
                logger.error(f"    ✗ Failed to generate/quantify NOMINAL prompt: {e}")
                continue

            # Generate FAILURE prompt (SHOULD cause vulnerability)
            task_counter += 1
            logger.info(f"  [{task_counter}/{total_tasks}] Generating FAILURE prompt {sample_idx}/{num_samples}")

            try:
                request = GenerateRequest(type=vuln_type, goal=Goal.FAILURE)
                failure_prompt = proposal_dist(request)
                logger.debug(f"    Prompt: {failure_prompt[:100]}...")

                # Quantify the failure prompt
                logger.debug(f"    Quantifying with threshold={variance_threshold}, min_rollouts={min_rollouts}")
                failure_result = quantify(
                    failure_prompt,
                    threshold=variance_threshold,
                    min_rollouts=min_rollouts
                )

                # Build and save record
                record = build_propose_record(
                    vulnerability_type=vuln_type,
                    goal="failure",
                    prompt=failure_prompt,
                    quantify_result=failure_result
                )
                append_propose_record(record, output_path)

                failure_count = failure_result.get("failure", 0)
                nominal_count = failure_result.get("nominal", 0)
                logger.info(f"    ✓ FAILURE prompt: {failure_count} failures, {nominal_count} successes")

            except Exception as e:
                logger.error(f"    ✗ Failed to generate/quantify FAILURE prompt: {e}")
                continue

        logger.info(f"  ✓ Completed {vuln_type}")

    logger.info(f"Completed! Processed {task_counter} tasks, results saved to {output_path}")


if __name__ == '__main__':
    main()

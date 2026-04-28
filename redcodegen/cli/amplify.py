import os
import sys
import typer
import jsonlines
import dspy
from collections import defaultdict
from datetime import datetime
from multiprocessing import Pool, Manager
from pathlib import Path
from threading import Thread
from typing import Any, Set
from loguru import logger

from redcodegen.constants import create_lm
from redcodegen.analyzers.common import AnalysisTool
from redcodegen.cli.app import app
from redcodegen.cli.common import is_data_record, normalize_record_samples
from redcodegen.cli.utils import LOG_FORMAT, configure_logging, get_model_config


def load_processed_scenarios(output_path: Path) -> Set[tuple[str, str]]:
    """Load scenarios that have already been processed.

    Returns:
        Set of (rule, seed) tuples that are already in the output file
    """
    processed: set[tuple[str, str]] = set()

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


def _serialize_chain(chain: list[tuple[str, Any, list[dict]]]) -> list[dict]:
    """Serialize an MCMC chain for JSONL output."""
    return [
        {
            "prompt": prompt,
            "num_successes": beta.nominal_pseudocounts - 1,
            "num_failures": beta.failure_pseudocounts - 1,
            "rollouts": rollouts,
        }
        for prompt, beta, rollouts in chain
    ]


def build_amplify_record(
    rule: str,
    seed: str,
    successes: list[tuple[str, Any, list[dict]]],
    failures: list[tuple[str, Any, list[dict]]],
    test_code: str | None,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Build an amplify record for JSONL output."""
    return {
        "type": rule,
        "seed": seed,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "tests": test_code,
        "mcmc_successes": _serialize_chain(successes),
        "mcmc_failures": _serialize_chain(failures),
        "metadata": metadata,
    }


def append_amplify_record(record: dict[str, Any], output_path: Path):
    """Append an amplified record to the JSONL file."""
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
    log_level: str,
    reasoning_effort: str | None = None,
    language: str = "python",
    test_model: str = "openai/gpt-5.3-codex",
    test_api_key: str | None = None,
    test_api_base: str | None = None,
    analysis_tool: str = "semgrep",
    no_successes: bool = False,
    summarize: bool = False,
):
    """Worker function that pulls tasks from queue and processes them."""
    # Import here to avoid issues with multiprocessing
    from redcodegen.kernels import LMRephrasingKernel
    from redcodegen.uncertainty import mcmc, rephrase_baseline
    from redcodegen.constants import create_lm
    from redcodegen.analyzers.common import AnalysisTool as AT
    from redcodegen.test_gen import generate_test_with_model, run_tests

    # Set up logging for this worker process
    from loguru import logger as worker_logger
    worker_logger.remove()
    worker_logger.add(
        sys.stderr, level=log_level, format=LOG_FORMAT,
        colorize=True, backtrace=True, diagnose=True,
    )

    # Each process needs its own DSPy configuration
    lm = create_lm(model_name=model, temperature=temperature, api_key=api_key, api_base=api_base, reasoning_effort=reasoning_effort)
    dspy.configure(lm=lm)

    # Set up test model for test generation
    test_lm = create_lm(
        model_name=test_model,
        temperature=temperature,
        api_key=test_api_key or api_key,
        api_base=test_api_base or api_base,
    )

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
            if summarize:
                # Baseline: rephrase the seed k times (no MCMC), then split by analyzer outcome
                worker_logger.debug("  Running rephrase baseline (--summarize)...")
                draws = rephrase_baseline(
                    seed,
                    LMRephrasingKernel(),
                    k=mcmc_steps,
                    threshold=variance_threshold,
                    language=language,
                    analysis_tool=AT(analysis_tool),
                )[1:]  # crop seed
                failures_mcmc = [s for s in draws if any(len(r["vulnerabilities"]) > 0 for r in s[2])]
                if no_successes:
                    successes = []
                    worker_logger.debug("  Skipping success bucket (--no-successes)")
                else:
                    successes = [s for s in draws if not any(len(r["vulnerabilities"]) > 0 for r in s[2])]
            else:
                # Run MCMC for successes (find non-vulnerable prompts)
                if no_successes:
                    successes = []
                    worker_logger.debug("  Skipping success MCMC chain (--no-successes)")
                else:
                    worker_logger.debug("  Running MCMC for successes...")
                    successes = mcmc(
                        seed,
                        LMRephrasingKernel(),
                        turns=mcmc_steps,
                        find_failure=False,
                        threshold=variance_threshold,
                        symmetric=True,
                        language=language,
                        analysis_tool=AT(analysis_tool),
                    )[1:]  # crop seed

                # Run MCMC for failures (find vulnerable prompts)
                worker_logger.debug("  Running MCMC for failures...")
                failures_mcmc = mcmc(
                    seed,
                    LMRephrasingKernel(),
                    turns=mcmc_steps,
                    find_failure=True,
                    threshold=variance_threshold,
                    symmetric=True,
                    language=language,
                    analysis_tool=AT(analysis_tool),
                )[1:]  # crop seed

            # Generate test from seed using test model
            test_code = None
            try:
                test_code = generate_test_with_model(seed, test_lm, language=language)
                worker_logger.debug("  Test generated successfully")
            except Exception as e:
                worker_logger.warning(f"  Test generation failed: {e}")

            # Run tests on MCMC rollouts (MCMC already did code gen + static analysis)
            def _add_test_results(chain):
                results = []
                for prompt, beta, rollouts in chain:
                    if test_code is not None:
                        for rollout in rollouts:
                            try:
                                test_result = run_tests(rollout["code"], test_code, language=language)
                                rollout["passes_tests"] = test_result["passed"]
                                rollout["test_details"] = {
                                    "num_tests": test_result["num_tests"],
                                    "num_passed": test_result["num_passed"],
                                    "num_failed": test_result["num_failed"],
                                    "results": test_result["test_results"],
                                }
                            except Exception as e:
                                worker_logger.warning(f"    Test run failed: {e}")
                    results.append((prompt, beta, rollouts))
                return results

            success_results = _add_test_results(successes)
            failure_results = _add_test_results(failures_mcmc)

            # Build record
            record = build_amplify_record(
                rule=rule,
                seed=seed,
                successes=success_results,
                failures=failure_results,
                test_code=test_code,
                metadata={
                    "turns": mcmc_steps,
                    "beta_variance_threshold": variance_threshold,
                    "analysis_tool": analysis_tool,
                    "method": "rephrase_baseline" if summarize else "mcmc",
                },
            )

            # Write directly to queue
            write_queue.put(record)
            worker_logger.info(
                f"  ✓ Completed {rule} "
                f"(successes: {len(successes)}, failures: {len(failures_mcmc)})"
            )

        except Exception as e:
            worker_logger.error(f"  ✗ Failed to amplify scenario for {rule}: {e}")
            continue


def file_writer_worker(write_queue, output_path: Path, total_scenarios: int):
    """Long-running thread that consumes records from queue and writes to file."""
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


def run_amplification(config):
    """Core amplification logic, callable from both CLI and sweep."""
    configure_logging(config.verbose)

    # Unpack config into local variables so existing logic stays unchanged
    language = config.language
    model = config.model
    api_key = config.api_key
    api_base = config.api_base
    temperature = config.temperature
    reasoning_effort = config.reasoning_effort
    test_model = config.test_model
    test_api_key = config.test_api_key
    test_api_base = config.test_api_base
    analysis_tool_str = config.analysis_tool
    analysis_tool = AnalysisTool(analysis_tool_str)
    mcmc_steps = config.mcmc_steps
    variance_threshold = config.variance_threshold
    no_successes = config.no_successes
    summarize = config.summarize
    filter_rule = config.filter_rule
    ignore_rule = config.ignore_rule
    verbose = config.verbose

    # Configure DSPy with specified model
    lm = create_lm(model_name=model, temperature=temperature, api_key=api_key, api_base=api_base, reasoning_effort=reasoning_effort)
    dspy.configure(lm=lm)
    logger.info(f"Configured model: {model}")
    logger.info(f"Test model: {test_model}")

    input_path = Path(config.input_file)
    output_path = Path(config.output)

    # Load input data
    logger.info(f"Loading input from {input_path}")
    try:
        with jsonlines.open(input_path) as reader:
            data = [record for record in reader if is_data_record(record)]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        raise typer.Exit(code=1)

    logger.info(f"Loaded {len(data)} records from input")

    # Extract all samples and filter to vulnerable ones
    all_samples = sum([normalize_record_samples(record) for record in data], [])
    vulnerable_samples = [s for s in all_samples if s.get("evaluation") and len(s["evaluation"]) > 0]

    if not vulnerable_samples:
        logger.warning("No vulnerable samples found in input file")
        return

    logger.info(f"Found {len(vulnerable_samples)} vulnerable samples")

    # Group by failure type (first evaluation rule)
    failures: dict[str, list] = defaultdict(list)
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
    n_workers = config.workers if config.workers is not None else os.cpu_count()
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

    log_level = "DEBUG" if verbose else "INFO"

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
        with Pool(processes=n_workers) as pool:
            worker_args = (
                task_queue,
                write_queue,
                mcmc_steps,
                variance_threshold,
                model,
                api_key,
                api_base,
                temperature,
                log_level,
                reasoning_effort,
                language,
                test_model,
                test_api_key,
                test_api_base,
                analysis_tool.value,
                no_successes,
                summarize,
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


@app.command()
def amplify(
    ctx: typer.Context,
    input_file: Path = typer.Option(..., "--input", "-i", help="Input JSONL file from generate command"),
    output: Path = typer.Option(..., "--output", "-o", help="Output JSONL file for amplified results"),
    mcmc_steps: int = typer.Option(16, "--mcmc-steps", help="Number of MCMC turns"),
    variance_threshold: float = typer.Option(0.015, "--variance-threshold", help="Beta variance threshold for stopping"),
    workers: int | None = typer.Option(None, "--workers", "-w", help="Number of parallel workers (default: CPU count)"),
    filter_rule: list[str] = typer.Option([], "--filter-rule", "-r", help="Specific rule(s) to process (can specify multiple times)"),
    ignore_rule: list[str] = typer.Option([], "--ignore-rule", "-x", help="Rule(s) to ignore/exclude (can specify multiple times)"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="Model identifier"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key (defaults to OPENAI_API_KEY env var)"),
    api_base: str | None = typer.Option(None, "--api-base", help="API base URL (defaults to OPENAI_API_BASE env var)"),
    temperature: float = typer.Option(0.8, "--temperature", help="Temperature for rephrasing"),
    reasoning_effort: str | None = typer.Option(None, "--reasoning-effort", help="Reasoning effort for model (low, medium, high)"),
    test_model: str = typer.Option("openai/gpt-5.3-codex", "--test-model", help="Model for test generation (trusted)"),
    test_api_key: str | None = typer.Option(None, "--test-api-key", help="API key for the test model (defaults to --api-key)"),
    test_api_base: str | None = typer.Option(None, "--test-api-base", help="Base URL for the test model API (defaults to --api-base)"),
    analysis_tool: AnalysisTool = typer.Option(AnalysisTool.SEMGREP.value, "--analysis-tool", "-a", help="Static analysis tool for evaluation"),
    num_rollouts: int = typer.Option(1, "--num-rollouts", "-k", help="Number of code rollouts per MCMC chain prompt"),
    no_successes: bool = typer.Option(False, "--no-successes", help="Skip success MCMC chain (only run failure chain)"),
    summarize: bool = typer.Option(False, "--summarize", help="Baseline mode: instead of MCMC, rephrase the seed k times and slice by static-analysis outcome"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """Amplify vulnerable scenarios using MCMC to explore failure boundaries.

    Takes output from 'generate' command and runs MCMC to find nearby prompts
    that both succeed (safe code) and fail (vulnerable code).
    """
    from redcodegen.config import AmplifyConfig

    ctx.ensure_object(dict)
    language = ctx.obj.get("language", "python")

    config = AmplifyConfig(
        input_file=str(input_file),
        output=str(output),
        mcmc_steps=mcmc_steps,
        variance_threshold=variance_threshold,
        workers=workers,
        filter_rule=filter_rule,
        ignore_rule=ignore_rule,
        model=model,
        api_key=api_key or os.getenv("OPENAI_API_KEY"),
        api_base=api_base or os.getenv("OPENAI_API_BASE"),
        temperature=temperature,
        reasoning_effort=reasoning_effort,
        test_model=test_model,
        test_api_key=test_api_key or os.getenv("TEST_LLM_API_KEY"),
        test_api_base=test_api_base or os.getenv("TEST_LLM_API_BASE"),
        analysis_tool=analysis_tool.value,
        num_rollouts=num_rollouts,
        no_successes=no_successes,
        summarize=summarize,
        language=language,
        verbose=verbose,
    )
    run_amplification(config)

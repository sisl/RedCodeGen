"""
main.py
Main script for generating and evaluating vulnerable code samples
"""

import rich_click as click
import jsonlines
import logging
import dspy
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Any
from cwe2.database import Database

from redcodegen.constants import CWE_TOP_25, create_lm

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
def amplify(input, output, mcmc_steps, variance_threshold, filter_rule, ignore_rule, model, api_key, api_base, temperature):
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

    # Process each failure type
    total_scenarios = sum(len(samples) for samples in failures.values())
    scenario_counter = 0

    for rule_idx, (rule, samples) in enumerate(failures.items(), 1):
        logger.info(f"Processing {len(samples)} scenarios for {rule} (rule {rule_idx}/{len(failures)})")

        for sample_idx, scenario in enumerate(samples, 1):
            scenario_counter += 1
            seed = scenario["scenario"]

            # Check if already processed
            if (rule, seed) in processed_scenarios:
                logger.debug(f"Skipping already-processed scenario: {rule}, {seed[:50]}...")
                continue

            logger.info(f"[{scenario_counter}/{total_scenarios}] Amplifying scenario for {rule}")
            logger.debug(f"  Seed: {seed[:50]}...")

            try:
                # Run MCMC for successes (find non-vulnerable prompts)
                logger.debug(f"  Running MCMC for successes...")
                successes = mcmc(
                    seed,
                    LMRephrasingKernel(),
                    turns=mcmc_steps,
                    find_failure=False,
                    threshold=variance_threshold,
                    symmetric=True
                )[1:] # crop seed

                # Run MCMC for failures (find vulnerable prompts)
                logger.debug(f"  Running MCMC for failures...")
                failures_mcmc = mcmc(
                    seed,
                    LMRephrasingKernel(),
                    turns=mcmc_steps,
                    find_failure=True,
                    threshold=variance_threshold,
                    symmetric=True
                )[1:] # crop seed

                # Build and save record
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

                append_amplify_record(record, output_path)
                logger.info(f"  ✓ Completed (successes: {len(successes)} chains, failures: {len(failures_mcmc)} chains)")

            except Exception as e:
                logger.error(f"  ✗ Failed to amplify scenario: {e}")
                continue

    logger.info(f"Completed! Processed scenarios saved to {output_path}")


if __name__ == '__main__':
    main()

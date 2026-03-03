import os
import typer
import jsonlines
import dspy
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Set
from loguru import logger

from redcodegen.constants import create_lm
from redcodegen.cli.app import app
from redcodegen.cli.utils import configure_logging, get_model_config


def load_processed_proposals(output_path: Path) -> dict[str, Set[str]]:
    """Load proposals that have already been processed.

    Returns:
        Dict mapping vulnerability_type to set of completed goals ('nominal', 'failure')
    """
    processed: dict[str, set[str]] = defaultdict(set)

    if not output_path.exists():
        return dict(processed)

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                if record.get("record_type") == "config":
                    continue
                if 'type' in record and 'goal' in record:
                    processed[record['type']].add(record['goal'])

        total_count = sum(len(goals) for goals in processed.values())
        logger.info(f"Found {total_count} already-processed proposals in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return dict(processed)


def build_propose_record(
    vulnerability_type: str,
    goal: str,
    prompt: str,
    quantify_result: Any,
) -> dict[str, Any]:
    """Build a propose record for JSONL output."""
    return {
        "type": vulnerability_type,
        "goal": goal,
        "prompt": prompt,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "result": {
            "failure": quantify_result[0].failure_pseudocounts - 1,
            "nominal": quantify_result[0].nominal_pseudocounts - 1,
            "error_types": list(quantify_result[1]),
        },
    }


def append_propose_record(record: dict[str, Any], output_path: Path):
    """Append a propose record to the JSONL file."""
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


@app.command()
def propose(
    output: Path = typer.Option(..., "--output", "-o", help="Output JSONL file for proposed prompts"),
    base_model: str = typer.Option(..., "--base-model", "-b", help="Base model for ProposalDistribution (e.g., Qwen/Qwen2.5-0.5B-Instruct)"),
    peft: str | None = typer.Option(None, "--peft", "-p", help="Optional PEFT adapter path"),
    num_samples: int = typer.Option(10, "--num-samples", "-n", help="Number of samples per vulnerability type"),
    variance_threshold: float = typer.Option(0.015, "--variance-threshold", help="Beta variance threshold for quantify"),
    min_rollouts: int = typer.Option(2, "--min-rollouts", help="Minimum rollouts for quantify"),
    vulnerabilities: list[str] = typer.Option([], "--vulnerabilities", "-v", help="Specific rule(s) to test (can specify multiple times)"),
    vulnerabilities_file: str | None = typer.Option(None, "--vulnerabilities-file", "-f", help="File containing rules to test (one per line)"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="Model identifier for code generation"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key (defaults to OPENAI_API_KEY env var)"),
    api_base: str | None = typer.Option(None, "--api-base", help="API base URL (defaults to OPENAI_API_BASE env var)"),
    temperature: float = typer.Option(0.8, "--temperature", help="Temperature for code generation"),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output"),
):
    """Generate and evaluate coding task prompts using a fine-tuned proposal model.

    Uses a ProposalDistribution (base model + optional PEFT) to generate
    prompts that either will or will not cause specific vulnerability types, then
    evaluates their reliability through multiple code generation rollouts.
    """
    configure_logging(verbose)

    # Configure DSPy with specified model for code generation
    lm = create_lm(
        model_name=model,
        temperature=temperature,
        api_key=api_key or os.getenv("OPENAI_API_KEY"),
        api_base=api_base or os.getenv("OPENAI_API_BASE"),
    )
    dspy.configure(lm=lm)
    logger.info(f"Configured code generation model: {model}")

    # Lazy-import heavy deps to avoid loading torch/transformers on --help
    from redcodegen.proposal import ProposalDistribution, GenerateRequest, Goal
    from redcodegen.uncertainty import quantify

    output_path = output

    # Initialize ProposalDistribution
    logger.info(f"Initializing ProposalDistribution with base model: {base_model}")
    if peft:
        logger.info(f"Using PEFT adapter: {peft}")

    try:
        proposal_dist = ProposalDistribution(base=base_model, peft=peft)
    except Exception as e:
        logger.error(f"Failed to initialize ProposalDistribution: {e}")
        raise typer.Exit(code=1)

    # Determine which vulnerabilities to test
    vulns_to_test: list[str] = []

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
            raise typer.Exit(code=1)

    # Check if we have any vulnerabilities
    if not vulns_to_test:
        logger.error("Must specify at least one vulnerability with --vulnerabilities/-v or --vulnerabilities-file/-f")
        raise typer.BadParameter("Must specify at least one vulnerability with --vulnerabilities/-v or --vulnerabilities-file/-f")

    # Remove duplicates while preserving order
    seen: set[str] = set()
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
                        return_evaluations=True,
                    )

                    # Build and save record
                    record = build_propose_record(
                        vulnerability_type=vuln_type,
                        goal="nominal",
                        prompt=nominal_prompt,
                        quantify_result=nominal_result,
                    )
                    append_propose_record(record, output_path)

                    fc = nominal_result[0].failure_pseudocounts - 1
                    nc = nominal_result[0].nominal_pseudocounts - 1
                    logger.info(f"    ✓ NOMINAL prompt: {fc} failures, {nc} successes")

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
                        return_evaluations=True,
                    )

                    # Build and save record
                    record = build_propose_record(
                        vulnerability_type=vuln_type,
                        goal="failure",
                        prompt=failure_prompt,
                        quantify_result=failure_result,
                    )
                    append_propose_record(record, output_path)

                    fc = failure_result[0].failure_pseudocounts - 1
                    nc = failure_result[0].nominal_pseudocounts - 1
                    logger.info(f"    ✓ FAILURE prompt: {fc} failures, {nc} successes")

                except Exception as e:
                    logger.error(f"    ✗ Failed to generate/quantify FAILURE prompt: {e}")
                    continue

        logger.info(f"  ✓ Completed {vuln_type}")

    logger.info(f"Completed! Processed {task_counter} tasks, results saved to {output_path}")

import os
import hashlib
import typer
import jsonlines
import dspy
from datetime import datetime
from pathlib import Path
from typing import Any, Set
from loguru import logger

from redcodegen.constants import create_lm
from redcodegen.cli.app import app
from redcodegen.cli.common import is_data_record
from redcodegen.cli.utils import configure_logging, get_model_config


def load_completed_rollouts(output_path: Path) -> Set[str]:
    """Load rollout prompts that have already been processed.

    Returns:
        Set of prompt SHA256 hashes already processed
    """
    completed: set[str] = set()

    if not output_path.exists():
        return completed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                if not is_data_record(record):
                    continue
                prompt_hash = record.get("prompt_sha256")
                if prompt_hash:
                    completed.add(prompt_hash)
        logger.info(f"Found {len(completed)} already-completed rollouts in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing rollout output file: {e}")

    return completed


def build_rollout_record(
    prompt: str,
    pairs: list[tuple[str, str, Any]],
    k: int,
    max_rollouts: int,
) -> dict[str, Any]:
    """Build a rollout record for JSONL output."""
    prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    pairs_out = [
        {
            "success": success,
            "failure": failure,
            "failure_info": failure_info,
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
        "pairs": pairs_out,
    }


def append_rollout_record(record: dict[str, Any], output_path: Path):
    """Append a rollout record to the JSONL file."""
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


@app.command()
def rollout(
    input: Path = typer.Option(..., "--input", "-i", help="Input JSONL file from amplify command"),
    output: Path = typer.Option(..., "--output", "-o", help="Output JSONL file for rollout pairs"),
    k: int = typer.Option(5, "--k", help="Number of success/failure pairs to collect per prompt"),
    max_rollouts: int = typer.Option(20, "--max-rollouts", help="Maximum rollouts to attempt per prompt"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="Model identifier for code generation"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key (defaults to OPENAI_API_KEY env var)"),
    api_base: str | None = typer.Option(None, "--api-base", help="API base URL (defaults to OPENAI_API_BASE env var)"),
    temperature: float = typer.Option(0.8, "--temperature", help="Temperature for code generation"),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output"),
):
    """Roll out amplified failure prompts to produce paired success/failure generations."""
    configure_logging(verbose)

    # Configure DSPy with specified model
    lm = create_lm(
        model_name=model,
        temperature=temperature,
        api_key=api_key or os.getenv("OPENAI_API_KEY"),
        api_base=api_base or os.getenv("OPENAI_API_BASE"),
    )
    dspy.configure(lm=lm)
    logger.info(f"Configured code generation model: {model}")

    from redcodegen.contrastive import rollout_k_pairs

    input_path = input
    output_path = output

    # Load amplify data
    logger.info(f"Loading amplified data from {input_path}")
    try:
        with jsonlines.open(input_path) as reader:
            data = [record for record in reader if is_data_record(record)]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        raise typer.Exit(code=1)

    if not data:
        logger.warning("No records found in input file")
        return

    # Extract prompts from mcmc_failures
    prompts: list[str] = []
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
    seen_prompts: set[str] = set()
    unique_prompts: list[str] = []
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
                max_rollouts=max_rollouts,
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

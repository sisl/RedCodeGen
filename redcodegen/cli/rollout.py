import os
import hashlib
import typer
import jsonlines
import dspy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Set
from loguru import logger

from redcodegen.constants import create_lm
from redcodegen.analyzers.common import AnalysisTool
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
    pairs: list[dict[str, Any]],
    test_code: str | None,
    k: int,
    max_rollouts: int,
) -> dict[str, Any]:
    """Build a rollout record for JSONL output."""
    prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    return {
        "prompt": prompt,
        "prompt_sha256": prompt_sha256,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "k": k,
        "max_rollouts": max_rollouts,
        "tests": test_code,
        "pairs": pairs,
    }


def append_rollout_record(record: dict[str, Any], output_path: Path):
    """Append a rollout record to the JSONL file."""
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


@app.command()
def rollout(
    ctx: typer.Context,
    input: Path = typer.Option(..., "--input", "-i", help="Input JSONL file from amplify command"),
    output: Path = typer.Option(..., "--output", "-o", help="Output JSONL file for rollout pairs"),
    k: int = typer.Option(5, "--k", help="Number of success/failure pairs to collect per prompt"),
    max_rollouts: int = typer.Option(20, "--max-rollouts", help="Maximum rollouts to attempt per prompt"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="Model identifier for code generation"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key (defaults to OPENAI_API_KEY env var)"),
    api_base: str | None = typer.Option(None, "--api-base", help="API base URL (defaults to OPENAI_API_BASE env var)"),
    temperature: float = typer.Option(0.8, "--temperature", help="Temperature for code generation"),
    coder_prompt: str | None = typer.Option(None, "--coder-prompt", "-c", help="Path to a JSON file with a hardened coder prompt to load"),
    test_model: str = typer.Option("openai/gpt-5.3-codex", "--test-model", help="Model for test generation (trusted)"),
    test_api_key: str | None = typer.Option(None, "--test-api-key", help="API key for the test model (defaults to --api-key)"),
    test_api_base: str | None = typer.Option(None, "--test-api-base", help="Base URL for the test model API (defaults to --api-base)"),
    analysis_tool: AnalysisTool = typer.Option(AnalysisTool.SEMGREP.value, "--analysis-tool", "-a", help="Static analysis tool for evaluation"),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output"),
):
    """Roll out amplified failure prompts to produce paired success/failure generations."""
    configure_logging(verbose)

    ctx.ensure_object(dict)
    language = ctx.obj.get("language", "python")

    resolved_api_key = api_key or os.getenv("OPENAI_API_KEY")
    resolved_api_base = api_base or os.getenv("OPENAI_API_BASE")

    # Configure DSPy with specified model
    lm = create_lm(
        model_name=model,
        temperature=temperature,
        api_key=resolved_api_key,
        api_base=resolved_api_base,
    )
    dspy.configure(lm=lm)
    logger.info(f"Configured code generation model: {model}")

    # Set up test model for test generation
    test_lm = create_lm(
        model_name=test_model,
        temperature=temperature,
        api_key=test_api_key or os.getenv("TEST_LLM_API_KEY") or resolved_api_key,
        api_base=test_api_base or os.getenv("TEST_LLM_API_BASE") or resolved_api_base,
    )
    logger.info(f"Test model: {test_model}")

    from redcodegen.contrastive import rollout_k_pairs
    from redcodegen.test_gen import generate_test_with_model, run_tests
    from redcodegen.analyzers.evaluate import evaluate

    # Load hardened coder prompt if provided
    if coder_prompt:
        from redcodegen.generator.prompting import load_coder
        load_coder(coder_prompt)
        logger.info(f"Loaded hardened coder prompt from {coder_prompt}")

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
            pairs_raw = rollout_k_pairs(prompt, k=k, max_rollouts=max_rollouts, language=language)

            # Generate test from prompt using test model
            test_code = None
            try:
                test_code = generate_test_with_model(prompt, test_lm, language=language)
                logger.debug("  Test generated successfully")
            except Exception as e:
                logger.warning(f"  Test generation failed: {e}")

            # Evaluate each code in the pairs: run tests + static analysis
            def _evaluate_code(code):
                passes_tests = None
                test_details = None
                if test_code is not None:
                    test_result = run_tests(code, test_code, language=language)
                    passes_tests = test_result["passed"]
                    test_details = {
                        "num_tests": test_result["num_tests"],
                        "num_passed": test_result["num_passed"],
                        "num_failed": test_result["num_failed"],
                        "results": test_result["test_results"],
                    }

                vulnerabilities = []
                try:
                    vulnerabilities = evaluate(code, analysis_tool=analysis_tool, language=language)
                except Exception as e:
                    logger.warning(f"    Evaluation failed: {e}")

                return {
                    "code": code,
                    "passes_tests": passes_tests,
                    "test_details": test_details,
                    "vulnerabilities": vulnerabilities,
                }

            # Evaluate all success/failure codes in parallel
            all_codes = []
            for success_code, failure_code, _ in pairs_raw:
                all_codes.extend([success_code, failure_code])

            with ThreadPoolExecutor(max_workers=min(len(all_codes), 8)) as executor:
                all_evals = list(executor.map(_evaluate_code, all_codes))

            # Reconstruct pairs from flat evaluation results
            pairs = []
            for i in range(0, len(all_evals), 2):
                pairs.append({
                    "success": all_evals[i],
                    "failure": all_evals[i + 1],
                })

            record = build_rollout_record(
                prompt=prompt,
                pairs=pairs,
                test_code=test_code,
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

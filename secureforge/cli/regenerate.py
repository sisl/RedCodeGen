import hashlib
import os
import typer
import jsonlines
import dspy
from datetime import datetime
from pathlib import Path
from typing import Any, Set
from loguru import logger

from secureforge.constants import create_lm
from secureforge.cli.app import app
from secureforge.cli.utils import configure_logging, get_model_config


def load_completed_examples(output_path: Path) -> Set[str]:
    """Load example file hashes that have already been processed.

    Returns:
        Set of example SHA256 hashes already in the output file
    """
    completed: set[str] = set()

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

    Returns:
        Set of (patch_sha256, file_path, example_sha256) tuples already in the output file
    """
    completed: set[tuple[str, str, str]] = set()

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


def build_example_record(
    example_path: str,
    example_sha256: str,
    scenarios: list[str],
    codes: list[str],
    evaluations: list[Any],
    min_scenarios: int,
) -> dict[str, Any]:
    """Build a record for example regeneration JSONL output."""
    samples = []
    for scenario, code, evaluation in zip(scenarios, codes, evaluations):
        samples.append({
            "scenario": scenario,
            "code": code,
            "evaluation": evaluation,
        })

    return {
        "example_path": example_path,
        "example_sha256": example_sha256,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "min_scenarios": min_scenarios,
        "samples": samples,
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
    scenarios: list[str],
    codes: list[str],
    evaluations: list[Any],
    min_scenarios: int,
) -> dict[str, Any]:
    """Build a record for patch regeneration JSONL output."""
    samples = []
    for scenario, code, evaluation in zip(scenarios, codes, evaluations):
        samples.append({
            "scenario": scenario,
            "code": code,
            "evaluation": evaluation,
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
        "samples": samples,
    }


def append_to_jsonl(record: dict[str, Any], output_path: Path):
    """Append a record to the JSONL file."""
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


def run_regeneration(config):
    """Core regeneration logic, callable from both CLI and sweep."""
    configure_logging(config.verbose)

    # Unpack config into local variables so existing logic stays unchanged
    input_dir = config.dir
    patches = config.patches
    min_samples = config.min_samples
    output_path = Path(config.output)
    model = config.model
    api_key = config.api_key
    api_base = config.api_base
    temperature = config.temperature
    checkpoint = config.checkpoint
    tk_checkpoint = config.tk_checkpoint
    tk_model = config.tk_model
    coder_prompt = config.coder_prompt

    # Configure DSPy with specified model
    lm = create_lm(
        model_name=model,
        temperature=temperature,
        api_key=api_key,
        api_base=api_base,
    )
    dspy.configure(lm=lm)
    logger.info(f"Configured model: {model}")

    # Import generator and validator after configuring dspy
    if tk_checkpoint is not None:
        if not tk_model:
            logger.error("--tk-model is required when using --tk-checkpoint")
            raise typer.Exit(code=1)
        from secureforge.generator.inference_tk import run_example, init_tk_model
        init_tk_model(tk_model, tk_checkpoint, temperature=temperature)
        logger.info(f"Using Tinker checkpoint: {tk_checkpoint} (model: {tk_model})")
    elif checkpoint is not None:
        from secureforge.generator.inference import run_example, init_model
        init_model(checkpoint, temperature=temperature)
        logger.info(f"Using local checkpoint: {checkpoint}")
    else:
        from secureforge.generator import run_example
    from secureforge.validator import evaluate

    # Load hardened coder prompt if provided
    if coder_prompt:
        from secureforge.generator.prompting import load_coder
        load_coder(coder_prompt)
        logger.info(f"Loaded hardened coder prompt from {coder_prompt}")

    if bool(input_dir) == bool(patches):
        logger.error("Must specify exactly one of --dir or --patches")
        raise typer.BadParameter("Must specify exactly one of --dir or --patches")

    if patches:
        from secureforge.patch import patched_changed_files

        input_path = Path(patches)
        logger.info(f"Loading patch records from {input_path}")
        try:
            with jsonlines.open(input_path) as reader:
                rows = [row for row in reader]
        except Exception as e:
            logger.error(f"Failed to read input file: {e}")
            raise typer.Exit(code=1)

        if not rows:
            logger.warning("No records found in input file")
            return

        required_keys = {"instance_id", "model", "repo", "base", "patch", "resolved"}
        processed = load_completed_patch_regenerations(output_path)

        valid_rows: list[tuple[dict, str, str]] = []
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
                    patch=patch_text,
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

                    evaluations: list[Any] = []
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
                        min_scenarios=min_samples,
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

    # --dir mode
    input_path = Path(input_dir)
    all_files = sorted([p for p in input_path.rglob("*") if p.is_file()], key=lambda p: str(p))
    if not all_files:
        logger.warning(f"No files found under {input_path}")
        return

    completed_hashes = load_completed_examples(output_path)

    files_to_process: list[tuple[Path, str, str]] = []
    skipped_completed = 0
    skipped_unreadable = 0
    for fp in all_files:
        try:
            content = fp.read_bytes()
        except Exception as e:
            skipped_unreadable += 1
            logger.warning(f"Skipping unreadable file {fp}: {e}")
            continue

        file_hash = hashlib.sha256(content).hexdigest()
        if file_hash in completed_hashes:
            skipped_completed += 1
            continue

        rel_path = str(fp.relative_to(input_path))
        files_to_process.append((fp, rel_path, file_hash))

    if not files_to_process:
        logger.info("All example files already completed!")
        return

    logger.info(
        f"Processing {len(files_to_process)} examples "
        f"(skipped {skipped_completed} already completed, {skipped_unreadable} unreadable)"
    )

    for idx, (fp, rel_path, file_hash) in enumerate(files_to_process, 1):
        logger.info(f"[{idx}/{len(files_to_process)}] Processing {rel_path}...")

        try:
            logger.info(f"  Generating {min_samples} code samples...")
            scenarios, codes = run_example(path=str(fp), min_scenarios=min_samples)
            logger.info(f"  Generated {len(codes)} code samples")

            scenarios = scenarios[:len(codes)]

            evaluations: list[Any] = []
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
                min_scenarios=min_samples,
            )

            append_to_jsonl(record, output_path)
            logger.info(f"✓ Completed {rel_path}")

        except Exception as e:
            logger.error(f"✗ Failed to process {rel_path}: {e}")
            continue

    logger.info(f"Completed! Results saved to {output_path}")


@app.command()
def regenerate(
    dir: str | None = typer.Option(None, "--dir", "-d", help="Input directory containing example files to regenerate"),
    patches: str | None = typer.Option(None, "--patches", help="Input JSONL file with patch records (same format as evaluate)"),
    min_samples: int = typer.Option(3, "--min-samples", "-n", help="Minimum samples per example"),
    output: Path = typer.Option("regenerate_results.jsonl", "--output", "-o", help="Output JSONL file"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="Model identifier"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key (defaults to OPENAI_API_KEY env var)"),
    api_base: str | None = typer.Option(None, "--api-base", help="API base URL (defaults to OPENAI_API_BASE env var)"),
    temperature: float = typer.Option(0.8, "--temperature", help="Temperature for code generation"),
    checkpoint: str | None = typer.Option(None, "--checkpoint", help="Path to local HuggingFace model checkpoint for code generation"),
    tk_checkpoint: str | None = typer.Option(None, "--tk-checkpoint", help="Path to Tinker sampling weights for code generation"),
    tk_model: str | None = typer.Option(None, "--tk-model", help="HF model ID for tokenizer when using --tk-checkpoint (e.g. Qwen/Qwen3-4B-Instruct-2507)"),
    coder_prompt: str | None = typer.Option(None, "--coder-prompt", "-c", help="Path to a JSON file with a hardened coder prompt to load"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """Regenerate code examples from a directory of example files or patch records."""
    from secureforge.config import RegenerateConfig
    config = RegenerateConfig(
        dir=dir,
        patches=patches,
        min_samples=min_samples,
        output=str(output),
        model=model,
        api_key=api_key or os.getenv("OPENAI_API_KEY"),
        api_base=api_base or os.getenv("OPENAI_API_BASE"),
        temperature=temperature,
        checkpoint=checkpoint,
        tk_checkpoint=tk_checkpoint,
        tk_model=tk_model,
        coder_prompt=coder_prompt,
        verbose=verbose,
    )
    run_regeneration(config)

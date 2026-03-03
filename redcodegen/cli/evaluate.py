import hashlib
import typer
import jsonlines
from datetime import datetime
from pathlib import Path
from typing import Any, Set
from loguru import logger

from redcodegen.cli.app import app
from redcodegen.cli.utils import configure_logging


def load_processed_patch_evaluations(output_path: Path) -> Set[tuple[str, str, str, str, str, str, bool]]:
    """Load patch evaluations that have already been processed.

    Returns:
        Set of processed keys:
        (instance_id, model, repo, base, resolved, patch_sha256, skip_patch)
    """
    processed: set[tuple[str, str, str, str, str, str, bool]] = set()

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
    row: dict[str, Any],
    patch_sha256: str,
    skip_patch: bool,
    evaluation: list[dict[str, Any]] | None,
    error: str | None,
) -> dict[str, Any]:
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
        "error": error,
    }


def append_patch_evaluation_record(record: dict[str, Any], output_path: Path):
    """Append a patch evaluation record to the JSONL file."""
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


@app.command()
def evaluate(
    input_file: Path = typer.Option(..., "--input", "-i", help="Input JSONL file with patch records to evaluate"),
    output: Path = typer.Option("patch_evaluations.jsonl", "--output", "-o", help="Output JSONL file for patch evaluation results"),
    workdir: Path = typer.Option("/tmp", "--workdir", help="Working directory for temporary CodeQL files"),
    skip_patch: bool = typer.Option(False, "--skip-patch", help="Skip applying patch; evaluate repository at base commit only"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """Evaluate patched repositories with CodeQL static analysis.

    Input JSONL rows must contain:
        instance_id, model, repo, base, patch, resolved
    """
    configure_logging(verbose)

    from redcodegen.patch import patched_evaluate

    input_path = input_file
    output_path = output
    workdir_path = workdir

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

    logger.info(f"Loaded {len(rows)} records from input")
    if skip_patch:
        logger.info("Patch application is disabled (--skip-patch); evaluating base commits only")

    required_keys = {"instance_id", "model", "repo", "base", "patch", "resolved"}
    processed = load_processed_patch_evaluations(output_path)

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
        row_key = (
            str(row["instance_id"]),
            str(row["model"]),
            str(row["repo"]),
            str(row["base"]),
            str(row["resolved"]),
            patch_sha256,
            bool(skip_patch),
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
    evaluation_cache: dict[tuple, tuple] = {}
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
                    skip_patch=skip_patch,
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
            error=error,
        )
        append_patch_evaluation_record(record, output_path)

    logger.info(
        f"Completed! Processed {len(valid_rows)} rows "
        f"(successes: {success_count}, failures: {failure_count}) saved to {output_path}"
    )

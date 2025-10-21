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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)


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


@click.command()
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
def main(cwes, use_top_25, min_samples, output, model, api_key):
    """Generate and evaluate vulnerable code samples for specified CWEs.

    Examples:
        python -m redcodegen -c 89 -c 79 # manually specify cwe
        python -m redcodegen -n 5 # specify number of rollouts
        python -m redcodegen --use-top-25 # run CWE top 25
        python -m redcodegen --use-top-25 -o results.jsonl # resume existing run
        python -m redcodegen --use-top-25 --model openai/gpt-4o # switch model
    """
    # Configure DSPy with specified model
    lm = create_lm(model_name=model, api_key=api_key)
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


if __name__ == '__main__':
    main()

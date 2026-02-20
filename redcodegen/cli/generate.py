import os
import typer
import jsonlines
import datetime
from pathlib import Path
from loguru import logger
from typing import Set, List, Dict, Any


import dspy
from cwe2.database import Database
from redcodegen.constants import CWE_TOP_25, create_lm


from redcodegen.cli.app import app
from redcodegen.config import GenerateConfig
from redcodegen.cli.utils import configure_logging, append_to_jsonl, get_model_config

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
        "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "min_scenarios": min_scenarios,
        "samples": samples
    }

def generate_scenarios(config: GenerateConfig):
    # Ensure we don't print the API key in logs
    safe_config = config.model_copy(update={"api_key": "***" if config.api_key else None})
    logger.debug(f"Starting generation with config: {safe_config}")

    # Configure DSPy with specified model
    lm = create_lm(model_name=config.model, temperature=config.temperature, api_key=config.api_key, api_base=config.api_base)
    dspy.configure(lm=lm)

    # Import generator and validator after configuring dspy
    from redcodegen.generator import run_cwe
    from redcodegen.validator import evaluate

    # Construct output path
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Construct output filename with model and temperature info
    temperature_str = f't{config.temperature}'.replace('.', 'p')
    model_str = config.model.split('/')[-1].replace('-', '_')  # Use model name for filename
    # datetime_str = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')
    output_filename = f"generated_scenarios_{model_str}_{temperature_str}_n{config.min_samples}.jsonl"
    output_path = output_dir / output_filename

    logger.info(f"Output will be saved to: {output_path.absolute()}")

    # Determine which CWEs to process
    if config.cwes:
        cwes_to_process = list(config.cwes)
        logger.info(f"Processing {len(cwes_to_process)} specified CWEs")
    elif config.use_top_25:
        cwes_to_process = CWE_TOP_25
        logger.info(f"Processing CWE Top 25 ({len(cwes_to_process)} CWEs)")
    else:
        logger.error("Must specify either --cwes or --use-top-25")
        raise typer.Exit(code=1)

    # Load already-completed CWEs for idempotency
    completed_cwes = load_completed_cwes(output_path)
    cwes_to_process = [cwe for cwe in cwes_to_process if cwe not in completed_cwes]

    if not cwes_to_process:
        logger.info("All CWEs already completed!")
        return

    logger.info(f"Processing {len(cwes_to_process)} CWEs (skipped {len(completed_cwes)} already completed)")

    # Initialize CWE database
    db = Database()

    # Track total scenarios and vulnerabilities for logging
    total_scenarios = 0
    total_vulnerabilities = 0
    total_scenarios_with_vulnerabilities = 0
    cwe_vulnerability_counts = {}

    # Process each CWE
    for idx, cwe_id in enumerate(cwes_to_process, 1):
        logger.info(f"[{idx}/{len(cwes_to_process)}] Processing CWE-{cwe_id}...")
        logger.info(f"  CWE-{cwe_id}: {db.get(cwe_id).name}")

        # Track vulnerabilities found for this CWE
        cwe_vulnerabilities = 0
        cwe_scenarios_with_vulnerabilities = 0

        try:
            # Get CWE metadata
            entry = db.get(cwe_id)
            cwe_name = entry.name
            cwe_description = entry.extended_description or entry.description

            # Generate code samples
            logger.info(f"  Generating at least {config.min_samples} code sample(s)...")
            codes = run_cwe(cwe_id, min_scenarios=config.min_samples)
            logger.info(f"  Generated {len(codes)} code samples")
            total_scenarios += len(codes)

            # Get scenarios (need to call generate again to get scenarios)
            from redcodegen.scenarios import generate
            scenario_data = generate(cwe_id, min_scenarios=config.min_samples)
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
                    cwe_vulnerabilities += len(evaluation)
                    total_vulnerabilities += len(evaluation)
                    if len(evaluation) > 0:
                        cwe_scenarios_with_vulnerabilities += 1
                        total_scenarios_with_vulnerabilities += 1
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
                min_scenarios=config.min_samples
            )
            cwe_vulnerability_counts[cwe_id] = {
                'vulnerabilities': cwe_vulnerabilities,
                'scenarios_with_vulnerabilities': cwe_scenarios_with_vulnerabilities,
                'scenarios': len(codes)
            }

            append_to_jsonl(record, output_path)
            logger.info(f"✓ Completed CWE-{cwe_id}. Current vulnerability rate: {total_scenarios_with_vulnerabilities}/{total_scenarios} ({(total_scenarios_with_vulnerabilities/total_scenarios)*100:.2f}%), vulnerabilities found so far: {total_vulnerabilities}")

        except Exception as e:
            logger.error(f"✗ Failed to process CWE-{cwe_id}: {e}")
            continue

    logger.info(f"Completed! Results saved to {output_path}")
    logger.info("Vulnerability counts per CWE:")
    for cwe_id, count in cwe_vulnerability_counts.items():
        logger.info(f"  CWE-{cwe_id}: {count['scenarios_with_vulnerabilities']} scenarios with vulnerabilities in {count['scenarios']} scenarios ({(count['scenarios_with_vulnerabilities']/count['scenarios'])*100:.2f}%), total vulnerabilities: {count['vulnerabilities']}")


@app.command()
def generate(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="The LLM model to use for generation"),
    temperature: float = typer.Option(0.8, "--temperature", "-t", help="Sampling temperature for generation"),
    cwes: list[str] = typer.Option([], "--cwe", "-c", help="List of CWEs to target (e.g., CWE-79)"),
    use_top_25: bool = typer.Option(False, "--use-top-25", help="Use the top 25 most common CWEs"),
    min_samples: int = typer.Option(3, "--min-samples", '-n', help="Minimum number of samples to generate per CWE"),
    output_dir: str = typer.Option('./output', "--output", "-o", help="Output directory for generated scenarios"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key for the LLM service"),
    api_base: str | None = typer.Option(None, "--api-base", help="Base URL for the LLM API"),
):
    """Generate scenarios that induce vulnerabilities in LLM-generated code.
    """

    config = GenerateConfig(
        verbose=verbose,
        model=model,
        temperature=temperature,
        cwes=cwes,
        use_top_25=use_top_25,
        min_samples=min_samples,
        output_dir=output_dir,
        api_key=api_key or os.getenv("LLM_API_KEY"),
        api_base=api_base or os.getenv("LLM_API_BASE"),
    )

    configure_logging(config.verbose)

    # Call the main generation function (to be implemented)
    generate_scenarios(config)

@app.command()
def generate_stats(filepath: Path = typer.Argument(..., help="Path to the JSONL file with generation results")):
    """Generate statistics from the results JSONL file."""
    # This function can be implemented to read the output JSONL and compute various statistics
    
    data = jsonlines.open(filepath)
    total_cwes = 0
    total_scenarios = 0
    total_vulnerabilities = 0
    cwe_vulnerability_counts = {}
    cwe_scenario_counts = {}
    cwe_scenarios_with_vulnerabilities = {}

    for record in data:
        cwe_id = record['cwe_id']
        scenarios = record['samples']
        vulnerabilities_in_cwe = sum(len(sample['evaluation']) for sample in scenarios if sample['evaluation'])
        total_vulnerabilities += vulnerabilities_in_cwe
        total_scenarios += len(scenarios)
        total_cwes += 1
        cwe_vulnerability_counts[cwe_id] = vulnerabilities_in_cwe
        cwe_scenario_counts[cwe_id] = len(scenarios)
        cwe_scenarios_with_vulnerabilities[cwe_id] = sum(1 for sample in scenarios if sample['evaluation'] and len(sample['evaluation']) > 0)

    logger.info(f"Total CWEs: {total_cwes}")
    logger.info(f"Total scenarios: {total_scenarios}")
    logger.info(f"Total vulnerabilities found: {total_vulnerabilities}")
    logger.info(f"Overall vulnerability rate: {(sum(cwe_scenarios_with_vulnerabilities.values())/total_scenarios)*100:.2f}%")
    logger.info("")
    logger.info("Vulnerabilities found per CWE:")
    for cwe_id, count in cwe_vulnerability_counts.items():
        logger.info(f"  CWE-{cwe_id:3d}: {count:3d} ({(cwe_scenarios_with_vulnerabilities[cwe_id]/cwe_scenario_counts[cwe_id])*100:.2f}%)")
    
    logger.info("")
    logger.info("Scenarios generated per CWE:")
    for cwe_id, scenario_count in cwe_scenario_counts.items():
        logger.info(f"  CWE-{cwe_id:3d}: {scenario_count} scenarios")
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
from redcodegen.analyzers.common import AnalysisTool
from redcodegen.config import GenerateConfig, RetryStrategy
from redcodegen.cli.utils import configure_logging, append_to_jsonl, get_model_config
from redcodegen.cli.app import app

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
    min_scenarios: int,
    test_codes: List[str | None] | None = None,
    tests_passed: List[bool | None] | None = None,
    retry_strategy: str | None = None,
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
        test_codes: Per-sample test source code (None when tests disabled)
        tests_passed: Per-sample test pass status (None when tests disabled)
        retry_strategy: Strategy used for test retries (None when tests disabled)

    Returns:
        Dict representing the complete record for this CWE
    """
    samples = []
    for i, (scenario, code, evaluation, error) in enumerate(
        zip(scenarios, codes, evaluations, errors)
    ):
        sample: Dict[str, Any] = {
            "scenario": scenario,
            "code": code,
            "evaluation": evaluation,
        }
        if test_codes is not None:
            sample["test_code"] = test_codes[i]
        if tests_passed is not None:
            sample["tests_passed"] = tests_passed[i]
        samples.append(sample)

    record = {
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "cwe_description": cwe_description,
        "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
        "model_config": get_model_config(),
        "min_scenarios": min_scenarios,
        "samples": samples,
    }
    if retry_strategy is not None:
        record["retry_strategy"] = retry_strategy
    return record

def generate_scenarios(config: GenerateConfig):
    # Ensure we don't print the API key in logs
    safe_config = config.model_copy(update={"api_key": "***" if config.api_key else None})
    logger.debug(f"Starting generation with config: {safe_config}")

    # Configure DSPy with specified model
    lm = create_lm(model_name=config.model, temperature=config.temperature, api_key=config.api_key, api_base=config.api_base)
    dspy.configure(lm=lm)

    # Import generator and validator after configuring dspy
    from redcodegen.generator import run_cwe, run_cwe_with_tests
    from redcodegen.analyzers.evaluate import evaluate

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
    total_tests_passed = 0
    total_tests_run = 0
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

            # Generate code samples (with or without tests)
            logger.info(f"  Generating at least {config.min_samples} code sample(s)...")

            if config.enable_tests:
                gen_results = run_cwe_with_tests(
                    cwe_id,
                    min_scenarios=config.min_samples,
                    max_retries=config.max_test_retries,
                    retry_strategy=config.retry_strategy,
                )
                scenarios = [r["scenario"] for r in gen_results]
                codes = [r["code"] for r in gen_results]
                test_codes = [r["test_code"] for r in gen_results]
                tests_passed_list = [r["tests_passed"] for r in gen_results]

                # Track test stats
                for tp in tests_passed_list:
                    if tp is not None:
                        total_tests_run += 1
                        if tp:
                            total_tests_passed += 1
            else:
                codes = run_cwe(cwe_id, min_scenarios=config.min_samples)
                from redcodegen.scenarios import generate as gen_scenarios
                scenario_data = gen_scenarios(cwe_id, min_scenarios=config.min_samples)
                scenarios = scenario_data["scenarios"][:len(codes)]
                test_codes = None
                tests_passed_list = None

            logger.info(f"  Generated {len(codes)} code samples")
            total_scenarios += len(codes)

            # Evaluate each code sample
            evaluations = []
            errors = []

            for i, code in enumerate(codes, 1):
                logger.info(f"  Evaluating sample {i}/{len(codes)}...")
                try:
                    evaluation = evaluate(code, analysis_tool=config.analysis_tool)
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
                min_scenarios=config.min_samples,
                test_codes=test_codes,
                tests_passed=tests_passed_list,
                retry_strategy=config.retry_strategy.value if config.enable_tests else None,
            )
            # Per-CWE test stats
            cwe_tests_run = 0
            cwe_tests_passed = 0
            if tests_passed_list is not None:
                for tp in tests_passed_list:
                    if tp is not None:
                        cwe_tests_run += 1
                        if tp:
                            cwe_tests_passed += 1

            cwe_vulnerability_counts[cwe_id] = {
                'vulnerabilities': cwe_vulnerabilities,
                'scenarios_with_vulnerabilities': cwe_scenarios_with_vulnerabilities,
                'scenarios': len(codes),
                'tests_run': cwe_tests_run,
                'tests_passed': cwe_tests_passed,
            }

            append_to_jsonl(record, output_path)

            status_parts = [
                f"vulnerability rate: {total_scenarios_with_vulnerabilities}/{total_scenarios} ({(total_scenarios_with_vulnerabilities/total_scenarios)*100:.2f}%)",
                f"vulnerabilities found so far: {total_vulnerabilities}",
            ]
            if config.enable_tests and total_tests_run > 0:
                status_parts.append(
                    f"test pass rate: {total_tests_passed}/{total_tests_run} ({(total_tests_passed/total_tests_run)*100:.2f}%)"
                )
            logger.info(f"✓ Completed CWE-{cwe_id}. {', '.join(status_parts)}")

        except Exception as e:
            logger.error(f"✗ Failed to process CWE-{cwe_id}: {e}")
            continue

    logger.info(f"Completed! Results saved to {output_path}")
    logger.info(f"Total scenarios: {total_scenarios}, vulnerabilities found: {total_vulnerabilities}")
    logger.info(f"Overall vulnerability rate: {total_scenarios_with_vulnerabilities}/{total_scenarios} ({(total_scenarios_with_vulnerabilities/total_scenarios)*100:.2f}%)")
    if total_tests_run > 0:
        logger.info(f"Overall test pass rate: {total_tests_passed}/{total_tests_run} ({(total_tests_passed/total_tests_run)*100:.2f}%)")
    logger.info("")

    # Unified per-CWE table sorted by decreasing vulnerability rate
    has_any_tests = any(c['tests_run'] > 0 for c in cwe_vulnerability_counts.values())
    sorted_cwes = sorted(
        cwe_vulnerability_counts.items(),
        key=lambda item: item[1]['scenarios_with_vulnerabilities'] / item[1]['scenarios'] if item[1]['scenarios'] > 0 else 0,
        reverse=True,
    )
    logger.info("Per CWE (sorted by vulnerability rate):")
    for cwe_id, c in sorted_cwes:
        vuln_rate = (c['scenarios_with_vulnerabilities'] / c['scenarios'] * 100) if c['scenarios'] > 0 else 0
        line = f"  CWE-{cwe_id:3d}: vulns {c['scenarios_with_vulnerabilities']:2d}/{c['scenarios']:<2d} ({vuln_rate:5.2f}%)"
        if has_any_tests and c['tests_run'] > 0:
            test_rate = c['tests_passed'] / c['tests_run'] * 100
            line += f", tests {c['tests_passed']:2d}/{c['tests_run']:<2d} ({test_rate:5.2f}%)"
        logger.info(line)


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
    analysis_tool: AnalysisTool = typer.Option(AnalysisTool.SEMGREP.value, "--analysis-tool", "-a", help="Static analysis tool to use for evaluation (e.g., codeql, semgrep, all)"),
    no_tests: bool = typer.Option(False, "--no-tests", help="Disable test generation and validation"),
    max_test_retries: int = typer.Option(3, "--max-test-retries", help="Max code generation retries when tests fail"),
    retry_strategy: RetryStrategy = typer.Option(RetryStrategy.REPAIR.value, "--retry-strategy", "-s", help="Retry strategy: 'repair' feeds errors back to LLM, 'regenerate' generates from scratch"),
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
        analysis_tool=analysis_tool,
        enable_tests=not no_tests,
        max_test_retries=max_test_retries,
        retry_strategy=retry_strategy,
    )

    configure_logging(config.verbose)

    # Call the main generation function (to be implemented)
    generate_scenarios(config)

@app.command()
def generate_stats(filepath: Path = typer.Argument(..., help="Path to the JSONL file with generation results")):
    """Generate statistics from the results JSONL file."""

    total_cwes = 0
    total_scenarios = 0
    total_vulnerabilities = 0
    total_tests_run = 0
    total_tests_passed = 0
    # Per-CWE stats: {cwe_id: {scenarios, vulns, scenarios_with_vulns, tests_run, tests_passed}}
    cwe_stats: Dict[int, Dict[str, int]] = {}

    with jsonlines.open(filepath) as reader:
        for record in reader:
            cwe_id = record['cwe_id']
            samples = record['samples']
            total_cwes += 1
            total_scenarios += len(samples)

            vulns = sum(len(s['evaluation']) for s in samples if s.get('evaluation'))
            scenarios_with_vulns = sum(1 for s in samples if s.get('evaluation') and len(s['evaluation']) > 0)
            total_vulnerabilities += vulns

            tests_run = 0
            tests_passed = 0
            for s in samples:
                tp = s.get("tests_passed")
                if tp is not None:
                    tests_run += 1
                    total_tests_run += 1
                    if tp:
                        tests_passed += 1
                        total_tests_passed += 1

            cwe_stats[cwe_id] = {
                'scenarios': len(samples),
                'vulns': vulns,
                'scenarios_with_vulns': scenarios_with_vulns,
                'tests_run': tests_run,
                'tests_passed': tests_passed,
            }

    # Overall summary
    total_scenarios_with_vulns = sum(c['scenarios_with_vulns'] for c in cwe_stats.values())
    vuln_rate = (total_scenarios_with_vulns / total_scenarios * 100) if total_scenarios > 0 else 0

    logger.info(f"Total CWEs: {total_cwes}")
    logger.info(f"Total scenarios: {total_scenarios}")
    logger.info(f"Total vulnerabilities found: {total_vulnerabilities}")
    logger.info(f"Overall vulnerability rate: {total_scenarios_with_vulns}/{total_scenarios} ({vuln_rate:.2f}%)")
    if total_tests_run > 0:
        test_rate = total_tests_passed / total_tests_run * 100
        logger.info(f"Test pass rate: {total_tests_passed}/{total_tests_run} ({test_rate:.2f}%)")
    logger.info("")

    # Unified per-CWE table sorted by decreasing vulnerability rate
    has_any_tests = total_tests_run > 0
    sorted_cwes = sorted(
        cwe_stats.items(),
        key=lambda item: item[1]['scenarios_with_vulns'] / item[1]['scenarios'] if item[1]['scenarios'] > 0 else 0,
        reverse=True,
    )
    logger.info("Per CWE (sorted by vulnerability rate):")
    for cwe_id, c in sorted_cwes:
        cwe_vuln_rate = (c['scenarios_with_vulns'] / c['scenarios'] * 100) if c['scenarios'] > 0 else 0
        line = f"  CWE-{cwe_id:3d}: vulns {c['scenarios_with_vulns']:2d}/{c['scenarios']:<2d} ({cwe_vuln_rate:5.2f}%)"
        if has_any_tests and c['tests_run'] > 0:
            cwe_test_rate = c['tests_passed'] / c['tests_run'] * 100
            line += f", tests {c['tests_passed']:2d}/{c['tests_run']:<2d} ({cwe_test_rate:5.2f}%)"
        logger.info(line)
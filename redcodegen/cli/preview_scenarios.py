import os
import datetime
import typer
import jsonlines
from pathlib import Path
from loguru import logger

import dspy
from redcodegen.constants import CWE_TOP_25, create_lm
from redcodegen.cli.utils import configure_logging
from redcodegen.cli.app import app


def write_jsonl_record(record: dict, output_path: Path):
    """Append a single CWE record to the JSONL file."""
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)


def write_markdown_report(all_records: list[dict], model_name: str, output_path: Path):
    """Write the full markdown report from all collected records."""
    lines = [
        "# Scenario Preview Report",
        "",
        f"Generated: {datetime.datetime.utcnow().isoformat()}Z",
        f"Model: {model_name}",
        "",
    ]

    for record in all_records:
        cwe_id = record["cwe_id"]
        cwe_name = record["cwe_name"]
        cwe_desc = record["cwe_description"]

        lines.append(f"## CWE-{cwe_id}: {cwe_name}")
        lines.append("")
        lines.append(f"**Description:** {cwe_desc}")
        lines.append("")

        for idx, stage in enumerate(record["stages"], 1):
            lines.append(f"### Scenario {idx}")
            lines.append("")
            lines.append("| Stage | Output |")
            lines.append("|-------|--------|")
            lines.append(f"| Raw scenario | {stage['raw_scenario']} |")
            if stage["stripped_scenario"] is not None:
                lines.append(f"| Stripped | {stage['stripped_scenario']} |")
            else:
                lines.append("| Stripped | _(skipped)_ |")
            if stage["suggested_library"] is not None:
                lines.append(f"| Library suggestion | {stage['suggested_library']} |")
            else:
                lines.append("| Library suggestion | _(none)_ |")
            if stage["rephrased_scenario"] is not None:
                lines.append(f"| Rephrased | {stage['rephrased_scenario']} |")
            else:
                lines.append("| Rephrased | _(unchanged)_ |")
            lines.append(f"| **Final** | **{stage['final_scenario']}** |")
            lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))


@app.command("preview-scenarios")
def preview_scenarios(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    cwes: list[str] = typer.Option([], "--cwe", "-c", help="List of CWEs to target (e.g., CWE-79)"),
    use_top_25: bool = typer.Option(False, "--use-top-25", help="Use the top 25 most common CWEs"),
    min_samples: int = typer.Option(10, "--min-samples", "-n", help="Number of scenarios to generate per CWE"),
    test_model: str = typer.Option("openai/gpt-5.3-codex", "--test-model", help="Model for scenario generation (trusted)"),
    test_api_key: str | None = typer.Option(None, "--test-api-key", help="API key for the test model"),
    test_api_base: str | None = typer.Option(None, "--test-api-base", help="Base URL for the test model API"),
    skip_strip: bool = typer.Option(False, "--skip-strip", help="Skip stripping vulnerability mentions"),
    risky: bool = typer.Option(False, "--risky", help="Use risky extraction"),
    jsonl_output: str | None = typer.Option(None, "--jsonl", help="Output path for JSONL file"),
    markdown_output: str | None = typer.Option(None, "--markdown", help="Output path for Markdown file"),
):
    """Preview scenario generation pipeline stages without running rollouts.

    Generates scenarios for the specified CWEs and saves every intermediate
    refinement stage (raw extraction, stripped, library suggestion, final)
    to JSONL and/or Markdown for inspection.
    """
    if jsonl_output is None and markdown_output is None:
        logger.error("At least one of --jsonl or --markdown must be provided")
        raise typer.Exit(code=1)

    configure_logging(verbose)

    ctx.ensure_object(dict)
    language = ctx.obj.get("language", "python")

    # Parse CWE strings (e.g. "CWE-79" or "79") to ints
    parsed_cwes = []
    for item in cwes:
        cleaned = item.strip()
        if cleaned.upper().startswith("CWE-"):
            cleaned = cleaned[4:]
        parsed_cwes.append(int(cleaned))

    if parsed_cwes:
        cwes_to_process = parsed_cwes
        logger.info(f"Processing {len(cwes_to_process)} specified CWEs")
    elif use_top_25:
        cwes_to_process = CWE_TOP_25
        logger.info(f"Processing CWE Top 25 ({len(cwes_to_process)} CWEs)")
    else:
        logger.error("Must specify either --cwe or --use-top-25")
        raise typer.Exit(code=1)

    # Create test model
    test_lm = create_lm(
        model_name=test_model,
        temperature=0.8,
        api_key=test_api_key or os.getenv("TEST_LLM_API_KEY"),
        api_base=test_api_base or os.getenv("TEST_LLM_API_BASE"),
    )
    dspy.configure(lm=test_lm)
    logger.info(f"Test model: {test_model}")

    from redcodegen.scenarios import generate as gen_scenarios

    all_records = []

    for idx, cwe_id in enumerate(cwes_to_process, 1):
        logger.info(f"[{idx}/{len(cwes_to_process)}] Processing CWE-{cwe_id}...")

        try:
            scenario_data = gen_scenarios(
                cwe_id,
                min_scenarios=min_samples,
                language=language,
                skip_strip=skip_strip,
                risky=risky,
                include_stages=True,
            )

            logger.info(f"  CWE-{cwe_id}: {scenario_data['name']}")

            record = {
                "cwe_id": cwe_id,
                "cwe_name": scenario_data["name"],
                "cwe_description": scenario_data["description"],
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "stages": scenario_data["stages"],
            }

            all_records.append(record)

            if jsonl_output:
                write_jsonl_record(record, Path(jsonl_output))

            logger.info(f"  Generated {len(scenario_data['stages'])} scenarios for CWE-{cwe_id}")

        except Exception as e:
            logger.error(f"Failed to process CWE-{cwe_id}: {e}")
            continue

    if markdown_output:
        write_markdown_report(all_records, test_model, Path(markdown_output))
        logger.info(f"Markdown report saved to {markdown_output}")

    logger.info(f"Done! Processed {len(all_records)} CWEs, "
                f"{sum(len(r['stages']) for r in all_records)} total scenarios")

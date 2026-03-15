import os
import typer
import jsonlines
from pathlib import Path
from loguru import logger
from typing import Any

import dspy
from redcodegen.constants import create_lm
from redcodegen.cli.app import app
from redcodegen.cli.common import is_data_record
from redcodegen.cli.utils import configure_logging
from redcodegen.analyzers.common import AnalysisTool
from redcodegen.optimize import OptimizeMethods


@app.command()
def optimize(
    ctx: typer.Context,
    input_file: Path = typer.Option(..., "--input", "-i", help="Input JSONL file from generate command"),
    output: Path = typer.Option("optimized.json", "--output", "-o", help="Output path for the optimized prompt (JSON)"),
    method: OptimizeMethods = typer.Option(OptimizeMethods.GEPA.value, "--method", help="Optimization method (gepa, mipro)"),
    analysis_tool: AnalysisTool = typer.Option(AnalysisTool.SEMGREP.value, "--analysis-tool", "-a", help="Static analysis tool for evaluation"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="Model for code generation (module under optimization)"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key for the code model"),
    api_base: str | None = typer.Option(None, "--api-base", help="Base URL for the code model API"),
    temperature: float = typer.Option(1.0, "--temperature", "-t", help="Sampling temperature"),
    reflection_model: str | None = typer.Option(None, "--reflection-model", help="Model for GEPA reflection (defaults to --model)"),
    auto: str | None = typer.Option("light", "--auto", help="Auto preset for optimizer (light, medium, heavy)"),
    coder_prompt: str | None = typer.Option(None, "--coder-prompt", "-c", help="Path to a JSON file with a hardened coder prompt to load before optimization"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """Optimize the code generation prompt to reduce vulnerabilities.

    Reads generation results (with vulnerable rollouts) and runs GEPA or MIPROv2
    to produce a hardened prompt that avoids generating vulnerable code.
    """
    configure_logging(verbose)

    ctx.ensure_object(dict)
    language = ctx.obj.get("language", "python")

    # Configure code model
    code_lm = create_lm(
        model_name=model,
        temperature=temperature,
        api_key=api_key or os.getenv("LLM_API_KEY"),
        api_base=api_base or os.getenv("LLM_API_BASE"),
    )
    dspy.configure(lm=code_lm)
    logger.info(f"Code model: {model}")

    # Build optimizer kwargs
    optimizer_kwargs: dict[str, Any] = {}
    if auto is not None:
        optimizer_kwargs["auto"] = auto

    if method == OptimizeMethods.GEPA and reflection_model:
        reflection_lm = create_lm(
            model_name=reflection_model,
            temperature=temperature,
            api_key=api_key or os.getenv("LLM_API_KEY"),
            api_base=api_base or os.getenv("LLM_API_BASE"),
        )
        optimizer_kwargs["reflection_lm"] = reflection_lm
        logger.info(f"Reflection model: {reflection_model}")

    # Load input data
    logger.info(f"Loading scenarios from {input_file}")
    all_scenarios: list[dict] = []
    try:
        with jsonlines.open(input_file) as reader:
            for record in reader:
                if not is_data_record(record):
                    continue
                all_scenarios.extend(record.get("scenarios", []))
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        raise typer.Exit(code=1)

    if not all_scenarios:
        logger.error("No scenarios found in input file")
        raise typer.Exit(code=1)

    vuln_count = sum(
        1
        for s in all_scenarios
        for r in s.get("rollouts", [])
        if len(r.get("vulnerabilities", [])) > 0
    )
    logger.info(f"Loaded {len(all_scenarios)} scenarios ({vuln_count} vulnerable rollouts)")

    # Optionally load a hardened coder prompt
    from redcodegen.optimize import optimize as run_optimize
    from redcodegen.generator.prompting import GenerateCode

    coder = dspy.ChainOfThought(GenerateCode)
    if coder_prompt:
        coder.load(coder_prompt)
        logger.info(f"Loaded coder prompt from {coder_prompt}")

    # Run optimization
    logger.info(f"Running {method.value} optimization...")
    optimized = run_optimize(
        scenarios=all_scenarios,
        method=method,
        analysis_tool=analysis_tool,
        language=language,
        coder=coder,
        **optimizer_kwargs,
    )

    # Save
    output.parent.mkdir(parents=True, exist_ok=True)
    optimized.save(str(output))
    logger.info(f"Optimized prompt saved to {output}")

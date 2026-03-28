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
    input_file: Path = typer.Option(..., "--input", "-i", help="Input JSONL file: from generate command (gepa/mipro/sft) or contrastive rollout pipeline (contrastive)"),
    output: Path = typer.Option(..., "--output", "-o", help="Output path: optimized prompt JSON (gepa/mipro) or HF model directory (sft/contrastive)"),
    method: OptimizeMethods = typer.Option(..., "--method", help="Optimization method (gepa, mipro, sft, sft_tk, contrastive, contrastive_tk)"),
    # Prompt optimization options (gepa, mipro)
    analysis_tool: AnalysisTool = typer.Option(AnalysisTool.SEMGREP.value, "--analysis-tool", "-a", help="[gepa/mipro] Static analysis tool for evaluation"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="[gepa/mipro] Model for code generation (module under optimization)"),
    api_key: str | None = typer.Option(None, "--api-key", help="[gepa/mipro] API key for the code model"),
    api_base: str | None = typer.Option(None, "--api-base", help="[gepa/mipro] Base URL for the code model API"),
    temperature: float = typer.Option(1.0, "--temperature", "-t", help="[gepa/mipro] Sampling temperature"),
    reflection_model: str | None = typer.Option(None, "--reflection-model", help="[gepa] Model for GEPA reflection (defaults to --model)"),
    auto: str | None = typer.Option("light", "--auto", help="[gepa/mipro] Auto preset for optimizer (light, medium, heavy)"),
    coder_prompt: str | None = typer.Option(None, "--coder-prompt", "-c", help="[gepa/mipro] Path to a JSON file with a hardened coder prompt to load before optimization"),
    # Training options (sft, contrastive)
    backbone: str = typer.Option("qwen", "--backbone", help="[sft/contrastive] Backbone architecture (qwen, llama, gpt_neox)"),
    implementation: str = typer.Option("Qwen/Qwen2.5-0.5B", "--implementation", help="[sft/contrastive] HF model ID for weights and tokenizer"),
    output_cache: Path = typer.Option("./output/models/", "--output-cache", help="[sft/contrastive] Cache folder for training artifacts"),
    run_name: str = typer.Option("rcg_run", "--run-name", help="[sft/contrastive] Experiment run name"),
    project: str = typer.Option("redcodegen", "--project", help="[sft/contrastive] W&B project name"),
    group: str = typer.Option("e0", "--group", help="[sft/contrastive] W&B group name"),
    batch_size: int = typer.Option(16, "--batch-size", help="[sft/contrastive] Effective batch size after gradient accumulation"),
    per_device_batch_size: int = typer.Option(2, "--per-device-batch-size", help="[sft/contrastive] Actual batch size per device per step"),
    lr: float = typer.Option(1e-4, "--lr", help="[sft/contrastive] Learning rate"),
    tokens: int = typer.Option(50_000, "--tokens", help="[sft/contrastive] Total number of training tokens"),
    wandb_enabled: bool = typer.Option(False, "--wandb", help="[sft/contrastive] Enable W&B logging"),
    # Tinker training options (sft_tk, contrastive_tk)
    epochs: int = typer.Option(10, "--epochs", help="[sft_tk/contrastive_tk] Number of training epochs"),
    seed: int = typer.Option(7, "--seed", help="[sft_tk/contrastive_tk] Random seed for shuffling"),
    lora_rank: int = typer.Option(32, "--lora-rank", help="[sft_tk/contrastive_tk] LoRA rank for the training adapter"),
    dpo_beta: float = typer.Option(0.1, "--dpo-beta", help="[contrastive_tk] DPO beta parameter"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """Optimize code generation to reduce vulnerabilities.

    Supports prompt optimization (GEPA, MIPROv2) and model fine-tuning (SFT,
    SFT_TK, contrastive, contrastive_tk). For prompt methods, reads generation
    results and produces a hardened prompt. For training methods, runs
    tokenization and training via theseus (sft/contrastive) or tinker
    (sft_tk/contrastive_tk).
    """
    configure_logging(verbose)

    ctx.ensure_object(dict)
    language = ctx.obj.get("language", "python")

    if method in (OptimizeMethods.SFT_TK, OptimizeMethods.CONTRASTIVE_TK):
        _run_training_tk(
            method=method,
            input_file=input_file,
            implementation=implementation,
            output_name=run_name,
            lr=lr,
            batch_size=batch_size,
            epochs=epochs,
            seed=seed,
            lora_rank=lora_rank,
            dpo_beta=dpo_beta,
        )
    elif method in (OptimizeMethods.SFT, OptimizeMethods.CONTRASTIVE):
        _run_training(
            method=method,
            input_file=input_file,
            backbone=backbone,
            implementation=implementation,
            output_cache=output_cache,
            output=output,
            run_name=run_name,
            project=project,
            group=group,
            batch_size=batch_size,
            per_device_batch_size=per_device_batch_size,
            lr=lr,
            tokens=tokens,
            wandb_enabled=wandb_enabled,
        )
    else:
        _run_prompt_optimization(
            method=method,
            input_file=input_file,
            output=output,
            analysis_tool=analysis_tool,
            language=language,
            model=model,
            api_key=api_key,
            api_base=api_base,
            temperature=temperature,
            reflection_model=reflection_model,
            auto=auto,
            coder_prompt=coder_prompt,
        )


def _run_prompt_optimization(
    method: OptimizeMethods,
    input_file: Path,
    output: Path,
    analysis_tool: AnalysisTool,
    language: str,
    model: str,
    api_key: str | None,
    api_base: str | None,
    temperature: float,
    reflection_model: str | None,
    auto: str | None,
    coder_prompt: str | None,
) -> None:
    """Run GEPA or MIPROv2 prompt optimization."""
    code_lm = create_lm(
        model_name=model,
        temperature=temperature,
        api_key=api_key or os.getenv("LLM_API_KEY"),
        api_base=api_base or os.getenv("LLM_API_BASE"),
    )
    dspy.configure(lm=code_lm)
    logger.info(f"Code model: {model}")

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

    from redcodegen.optimize import optimize as run_optimize
    from redcodegen.generator.prompting import GenerateCode

    coder = dspy.ChainOfThought(GenerateCode)
    if coder_prompt:
        coder.load(coder_prompt)
        logger.info(f"Loaded coder prompt from {coder_prompt}")

    logger.info(f"Running {method.value} optimization...")
    optimized = run_optimize(
        scenarios=all_scenarios,
        method=method,
        analysis_tool=analysis_tool,
        language=language,
        coder=coder,
        **optimizer_kwargs,
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    optimized.save(str(output))
    logger.info(f"Optimized prompt saved to {output}")


def _run_training(
    method: OptimizeMethods,
    input_file: Path,
    backbone: str,
    implementation: str,
    output_cache: Path,
    output: Path,
    run_name: str,
    project: str,
    group: str,
    batch_size: int,
    per_device_batch_size: int,
    lr: float,
    tokens: int,
    wandb_enabled: bool,
) -> None:
    """Run SFT or contrastive model training."""
    logger.info(f"Running {method.value} training: {implementation} ({backbone})")

    if method == OptimizeMethods.SFT:
        from redcodegen.optimize import run_sft

        run_sft(
            config_path=input_file,
            implementation=implementation,
            backbone=backbone,
            out_folder=output_cache,
            run_name=run_name,
            project=project,
            group=group,
            batch_size=batch_size,
            per_device_batch_size=per_device_batch_size,
            lr=lr,
            wandb_enabled=wandb_enabled,
            tokens=tokens,
            hf_output=output,
        )
    elif method == OptimizeMethods.CONTRASTIVE:
        from redcodegen.optimize import run_contrastive

        run_contrastive(
            config_path=input_file,
            implementation=implementation,
            backbone=backbone,
            out_folder=output_cache,
            run_name=run_name,
            project=project,
            group=group,
            batch_size=batch_size,
            per_device_batch_size=per_device_batch_size,
            lr=lr,
            wandb_enabled=wandb_enabled,
            tokens=tokens,
            hf_output=output,
        )

    logger.info(f"{method.value} training complete.")


def _run_training_tk(
    method: OptimizeMethods,
    input_file: Path,
    implementation: str,
    output_name: str,
    lr: float,
    batch_size: int,
    epochs: int,
    seed: int,
    lora_rank: int,
    dpo_beta: float,
) -> None:
    """Run Tinker-based training (SFT or DPO contrastive)."""
    logger.info(f"Running Tinker {method.value} training: {implementation}")

    if method == OptimizeMethods.SFT_TK:
        from redcodegen.optimize import run_sft_tk

        sampling_path = run_sft_tk(
            config_path=input_file,
            implementation=implementation,
            output_name=output_name,
            lr=lr,
            batch_size=batch_size,
            epochs=epochs,
            seed=seed,
            lora_rank=lora_rank,
        )
    elif method == OptimizeMethods.CONTRASTIVE_TK:
        from redcodegen.optimize import run_contrastive_tk

        sampling_path = run_contrastive_tk(
            config_path=input_file,
            implementation=implementation,
            output_name=output_name,
            lr=lr,
            batch_size=batch_size,
            epochs=epochs,
            seed=seed,
            dpo_beta=dpo_beta,
            lora_rank=lora_rank,
        )

    logger.info(f"Tinker {method.value} training complete. Sampling weights: {sampling_path}")

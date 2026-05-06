import os
import json
import typer
import jsonlines
import datetime
from pathlib import Path
from loguru import logger
from typing import Dict, Any, Tuple


import dspy
from cwe2.database import Database
from redcodegen.constants import CWE_TOP_25, create_lm
from redcodegen.analyzers.common import AnalysisTool
from redcodegen.config import IterateConfig
from redcodegen.cli.common import is_data_record, read_config_record
from redcodegen.cli.utils import configure_logging, append_to_jsonl, get_model_config, get_environment_info, FailedPromptCallback
from redcodegen.cli.app import app


ScenariosByCWE = Dict[int, Dict[int, Dict[str, Any]]]
RolloutsByScenario = Dict[Tuple[int, int], list]


def load_iterate_state(output_path: Path) -> Tuple[ScenariosByCWE, RolloutsByScenario]:
    """Reconstruct state from a partial JSONL file for resumption.

    Returns:
        scenarios_by_cwe: cwe_id -> {scenario_idx -> {scenario, tests, cwe_description}}
        rollouts_by_scenario: (cwe_id, scenario_idx) -> list of rollout records (in file order)
    """
    scenarios_by_cwe: ScenariosByCWE = {}
    rollouts_by_scenario: RolloutsByScenario = {}

    if not output_path.exists():
        return scenarios_by_cwe, rollouts_by_scenario

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                if not is_data_record(record):
                    continue
                rtype = record.get("record_type")
                if rtype == "scenario":
                    cwe_id = record["cwe_id"]
                    s_idx = record["scenario_idx"]
                    scenarios_by_cwe.setdefault(cwe_id, {})[s_idx] = {
                        "scenario": record["scenario"],
                        "tests": record.get("tests"),
                        "cwe_description": record.get("cwe_description"),
                    }
                elif rtype == "rollout":
                    key = (record["cwe_id"], record["scenario_idx"])
                    rollouts_by_scenario.setdefault(key, []).append(record)
        n_scenarios = sum(len(v) for v in scenarios_by_cwe.values())
        n_rollouts = sum(len(v) for v in rollouts_by_scenario.values())
        logger.info(
            f"Resumed from {output_path}: "
            f"{n_scenarios} scenario(s) across {len(scenarios_by_cwe)} CWE(s), "
            f"{n_rollouts} rollout(s)"
        )
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return scenarios_by_cwe, rollouts_by_scenario


def is_scenario_done(rollouts: list, max_rollouts: int) -> bool:
    """A scenario is done if it has a rollout with stop_reason set, or hit the cap."""
    if len(rollouts) >= max_rollouts:
        return True
    for r in rollouts:
        if r.get("stop_reason"):
            return True
    return False


def iterate_scenarios(config: IterateConfig):
    safe_config = config.model_copy(update={
        "api_key": "***" if config.api_key else None,
        "test_api_key": "***" if config.test_api_key else None,
    })
    logger.debug(f"Starting iterate with config: {safe_config}")

    if config.debug_log:
        debug_callback = FailedPromptCallback(Path(config.debug_log))
        existing_callbacks = list(dspy.settings.get("callbacks", []) or [])
        dspy.configure(callbacks=existing_callbacks + [debug_callback])
        logger.info(f"Debug log enabled: failing LM prompts will be written to {debug_callback.log_path.absolute()}")

    test_lm = create_lm(
        model_name=config.test_model,
        temperature=config.temperature,
        api_key=config.test_api_key,
        api_base=config.test_api_base,
    )
    logger.info(f"Test model: {config.test_model}")

    if config.tk_checkpoint:
        if not config.tk_model:
            logger.error("--tk-model is required when using --tk-checkpoint")
            raise typer.Exit(code=1)
        from redcodegen.generator.inference_tk import init_tk_model
        from redcodegen.generator.inference_tk import run_k
        init_tk_model(config.tk_model, config.tk_checkpoint, temperature=config.temperature)
        dspy.configure(lm=test_lm)
        logger.info(f"Using Tinker checkpoint: {config.tk_checkpoint} (model: {config.tk_model})")
    elif config.checkpoint:
        from redcodegen.generator.inference import init_model
        from redcodegen.generator.inference import run_k
        init_model(config.checkpoint, temperature=config.temperature)
        dspy.configure(lm=test_lm)
        logger.info(f"Using local checkpoint: {config.checkpoint}")
    else:
        code_lm = create_lm(
            model_name=config.model,
            temperature=config.temperature,
            api_key=config.api_key,
            api_base=config.api_base,
            reasoning_effort=config.reasoning_effort,
        )
        dspy.configure(lm=code_lm)
        from redcodegen.generator import run_k
    from redcodegen.scenarios import generate as gen_scenarios
    from redcodegen.test_gen import generate_test_with_model, run_tests
    from redcodegen.analyzers.evaluate import evaluate

    mode_flags = [
        ("--secure", config.secure),
        ("--barebones", config.barebones),
        ("--coder-prompt", bool(config.coder_prompt)),
    ]
    active = [name for name, on in mode_flags if on]
    if len(active) > 1:
        logger.error(f"{', '.join(active)} are mutually exclusive (each targets a different coder signature)")
        raise typer.Exit(code=1)
    if config.coder_prompt:
        from redcodegen.generator.prompting import load_coder
        load_coder(config.coder_prompt)
        logger.info(f"Loaded hardened coder prompt from {config.coder_prompt}")
    if config.secure:
        from redcodegen.generator.prompting import set_secure
        set_secure(True)
        logger.info("Secure-coder mode enabled: using security-hardened code-generation signature")
    if config.barebones:
        from redcodegen.generator.prompting import set_barebones
        set_barebones(True)
        logger.info("Barebones-coder mode enabled: using minimal code-generation signature")

    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    temperature_str = f't{config.temperature}'.replace('.', 'p')
    if config.tk_checkpoint:
        model_str = "tk_" + Path(config.tk_checkpoint).name.replace('-', '_')
    elif config.checkpoint:
        model_str = Path(config.checkpoint).name.replace('-', '_')
    else:
        model_str = config.model.split('/')[-1].replace('-', '_')
    re_suffix = f"_re{config.reasoning_effort}" if config.reasoning_effort else ""
    mode_suffix = "_secure" if config.secure else ("_barebones" if config.barebones else "")
    output_filename = f"iterate_{model_str}_{temperature_str}_n{config.min_samples}_max{config.max_rollouts_per_scenario}{re_suffix}{mode_suffix}.jsonl"
    output_path = output_dir / output_filename

    logger.info(f"Output will be saved to: {output_path.absolute()}")

    if not output_path.exists():
        config_record = {
            "record_type": "config",
            "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
            "config": config.to_record(),
            "environment": get_environment_info(),
            "model_config": {
                **get_model_config(),
                "test_model": config.test_model,
            },
        }
        with jsonlines.open(output_path, mode='a') as writer:
            writer.write(config_record)
        logger.info("Wrote config record to output file")

    if config.cwes:
        cwes_to_process = list(config.cwes)
        logger.info(f"Processing {len(cwes_to_process)} specified CWEs")
    elif config.use_top_25:
        cwes_to_process = CWE_TOP_25
        logger.info(f"Processing CWE Top 25 ({len(cwes_to_process)} CWEs)")
    else:
        logger.error("Must specify either --cwes or --use-top-25")
        raise typer.Exit(code=1)

    scenarios_by_cwe, rollouts_by_scenario = load_iterate_state(output_path)

    db = Database()

    total_scenarios = 0
    total_rollouts = 0
    total_rollouts_passing = 0
    total_rollouts_clean = 0
    total_scenarios_clean = 0
    total_scenarios_capped = 0

    for idx, cwe_id in enumerate(cwes_to_process, 1):
        logger.info(f"[{idx}/{len(cwes_to_process)}] Processing CWE-{cwe_id}...")

        try:
            existing_scenarios = scenarios_by_cwe.get(cwe_id, {})

            if existing_scenarios:
                ordered = sorted(existing_scenarios.items())
                scenarios = [v["scenario"] for _, v in ordered]
                tests_per_scenario = [v["tests"] for _, v in ordered]
                cwe_description = next(
                    (v.get("cwe_description") for _, v in ordered if v.get("cwe_description")),
                    None,
                )
                if cwe_description is None:
                    entry = db.get(cwe_id)
                    cwe_description = entry.extended_description or entry.description
                logger.info(f"  CWE-{cwe_id}: replaying {len(scenarios)} persisted scenario(s)")

                all_done = all(
                    is_scenario_done(
                        rollouts_by_scenario.get((cwe_id, s_idx), []),
                        config.max_rollouts_per_scenario,
                    )
                    for s_idx, _ in ordered
                )
                if all_done:
                    logger.info(f"  CWE-{cwe_id}: all persisted scenarios already complete, skipping")
                    for s_idx, _ in ordered:
                        rollouts = rollouts_by_scenario.get((cwe_id, s_idx), [])
                        total_scenarios += 1
                        total_rollouts += len(rollouts)
                        total_rollouts_passing += sum(1 for r in rollouts if r.get("passes_tests") is True)
                        total_rollouts_clean += sum(1 for r in rollouts if not r.get("vulnerabilities"))
                        if any(r.get("stop_reason") == "no_vulnerability" for r in rollouts):
                            total_scenarios_clean += 1
                        elif any(r.get("stop_reason") == "max_rollouts_reached" for r in rollouts):
                            total_scenarios_capped += 1
                    continue
            else:
                entry = db.get(cwe_id)
                cwe_description = entry.extended_description or entry.description
                logger.info(f"  CWE-{cwe_id}: {entry.name}")

                logger.info(f"  Generating {config.min_samples} scenario(s) using test model...")
                with dspy.settings.context(lm=test_lm):
                    scenario_data = gen_scenarios(cwe_id, min_scenarios=config.min_samples, language=config.language)
                generated = scenario_data["scenarios"][:config.min_samples]

                tests_per_scenario = []
                for scenario in generated:
                    test_code = None
                    try:
                        test_code = generate_test_with_model(scenario, test_lm, language=config.language)
                        logger.info("    Test generated successfully")
                    except Exception as e:
                        logger.warning(f"    Test generation failed: {e}")
                    tests_per_scenario.append(test_code)

                with jsonlines.open(output_path, mode='a') as writer:
                    for s_idx, (scenario, tests) in enumerate(zip(generated, tests_per_scenario)):
                        writer.write({
                            "record_type": "scenario",
                            "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
                            "cwe_id": cwe_id,
                            "cwe_description": cwe_description,
                            "scenario_idx": s_idx,
                            "scenario": scenario,
                            "tests": tests,
                        })
                logger.info(f"  Persisted {len(generated)} scenario record(s) for CWE-{cwe_id}")
                scenarios = generated

            for s_idx, (scenario, test_code) in enumerate(zip(scenarios, tests_per_scenario)):
                logger.info(
                    f"  Scenario {s_idx + 1}/{len(scenarios)}: "
                    f"{scenario[:80]}{'...' if len(scenario) > 80 else ''}"
                )

                existing_rollouts = list(rollouts_by_scenario.get((cwe_id, s_idx), []))

                if is_scenario_done(existing_rollouts, config.max_rollouts_per_scenario):
                    logger.info(f"    Scenario {s_idx + 1} already complete ({len(existing_rollouts)} rollout(s) on disk), skipping")
                    total_scenarios += 1
                    total_rollouts += len(existing_rollouts)
                    total_rollouts_passing += sum(1 for r in existing_rollouts if r.get("passes_tests") is True)
                    total_rollouts_clean += sum(1 for r in existing_rollouts if not r.get("vulnerabilities"))
                    if any(r.get("stop_reason") == "no_vulnerability" for r in existing_rollouts):
                        total_scenarios_clean += 1
                    elif any(r.get("stop_reason") == "max_rollouts_reached" for r in existing_rollouts):
                        total_scenarios_capped += 1
                    continue

                start_idx = len(existing_rollouts)
                if start_idx > 0:
                    logger.info(f"    Resuming at rollout_idx={start_idx} ({config.max_rollouts_per_scenario - start_idx} remaining)")

                scenario_rollouts = list(existing_rollouts)
                scenario_clean = False
                scenario_capped = False

                for r_idx in range(start_idx, config.max_rollouts_per_scenario):
                    is_last = (r_idx == config.max_rollouts_per_scenario - 1)

                    code = None
                    passes_tests = None
                    test_details = None
                    vulnerabilities = []
                    error = None

                    try:
                        codes = run_k(scenario, 1, test_code=test_code or "", language=config.language, rollout_offset=r_idx)
                        if not codes:
                            raise RuntimeError("run_k returned no code samples")
                        code = codes[0]

                        if test_code is not None:
                            try:
                                test_result = run_tests(code, test_code, language=config.language)
                                passes_tests = test_result["passed"]
                                test_details = {
                                    "num_tests": test_result["num_tests"],
                                    "num_passed": test_result["num_passed"],
                                    "num_failed": test_result["num_failed"],
                                    "results": test_result["test_results"],
                                }
                            except Exception as e:
                                logger.warning(f"    Test execution failed: {e}")

                        try:
                            vulnerabilities = evaluate(code, analysis_tool=config.analysis_tool, language=config.language)
                        except Exception as e:
                            logger.warning(f"    Evaluation failed: {e}")
                    except Exception as e:
                        error = f"{type(e).__name__}: {e}"
                        logger.warning(f"    Rollout {r_idx} failed: {error}")
                        if config.debug_log:
                            import traceback as _tb
                            try:
                                with open(config.debug_log, 'a') as f:
                                    f.write(json.dumps({
                                        "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
                                        "cwe_id": cwe_id,
                                        "scenario_idx": s_idx,
                                        "rollout_idx": r_idx,
                                        "stage": "rollout",
                                        "exception_type": type(e).__name__,
                                        "exception": str(e),
                                        "traceback": _tb.format_exc(),
                                    }, default=str) + '\n')
                            except Exception as write_err:
                                logger.warning(f"Failed to write debug log entry: {write_err}")

                    stop_reason = None
                    if error is None and len(vulnerabilities) == 0:
                        stop_reason = "no_vulnerability"
                        scenario_clean = True
                    elif is_last:
                        stop_reason = "max_rollouts_reached"
                        scenario_capped = True

                    rollout_record = {
                        "record_type": "rollout",
                        "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
                        "cwe_id": cwe_id,
                        "scenario_idx": s_idx,
                        "rollout_idx": r_idx,
                        "code": code,
                        "passes_tests": passes_tests,
                        "test_details": test_details,
                        "vulnerabilities": vulnerabilities,
                        "stop_reason": stop_reason,
                        "error": error,
                    }
                    append_to_jsonl(rollout_record, output_path)
                    scenario_rollouts.append(rollout_record)

                    if stop_reason == "no_vulnerability":
                        logger.info(f"    Rollout {r_idx}: clean — stopping scenario early")
                        break
                    if stop_reason == "max_rollouts_reached":
                        logger.info(f"    Rollout {r_idx}: hit cap of {config.max_rollouts_per_scenario}")
                        break

                total_scenarios += 1
                total_rollouts += len(scenario_rollouts)
                total_rollouts_passing += sum(1 for r in scenario_rollouts if r.get("passes_tests") is True)
                total_rollouts_clean += sum(1 for r in scenario_rollouts if not r.get("vulnerabilities") and r.get("error") is None)
                if scenario_clean:
                    total_scenarios_clean += 1
                if scenario_capped:
                    total_scenarios_capped += 1

            logger.info(f"✓ Completed CWE-{cwe_id}")

        except Exception as e:
            logger.error(f"✗ Failed to process CWE-{cwe_id}: {e}")
            if config.debug_log:
                import traceback as _tb
                try:
                    with open(config.debug_log, 'a') as f:
                        f.write(json.dumps({
                            "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
                            "cwe_id": cwe_id,
                            "stage": "cwe_processing",
                            "exception_type": type(e).__name__,
                            "exception": str(e),
                            "traceback": _tb.format_exc(),
                        }, default=str) + '\n')
                except Exception as write_err:
                    logger.warning(f"Failed to write debug log entry: {write_err}")
            continue

    logger.info(f"Completed! Results saved to {output_path}")
    logger.info(f"Total scenarios: {total_scenarios}, total rollouts: {total_rollouts}")
    if total_scenarios > 0:
        clean_rate = total_scenarios_clean / total_scenarios * 100
        cap_rate = total_scenarios_capped / total_scenarios * 100
        logger.info(f"Scenarios reaching clean code: {total_scenarios_clean}/{total_scenarios} ({clean_rate:.2f}%)")
        logger.info(f"Scenarios hitting cap:         {total_scenarios_capped}/{total_scenarios} ({cap_rate:.2f}%)")
    if total_rollouts > 0:
        pass_rate = total_rollouts_passing / total_rollouts * 100
        logger.info(f"Test pass rate: {total_rollouts_passing}/{total_rollouts} ({pass_rate:.2f}%)")


@app.command()
def iterate(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="The LLM model to use for code generation (model under test)"),
    temperature: float = typer.Option(1.0, "--temperature", "-t", help="Sampling temperature for generation"),
    cwes: list[str] = typer.Option([], "--cwe", help="List of CWEs to target (e.g., CWE-79)"),
    use_top_25: bool = typer.Option(False, "--use-top-25", help="Use the top 25 most common CWEs"),
    min_samples: int = typer.Option(3, "--min-samples", '-n', help="Number of scenarios to generate per CWE"),
    max_rollouts_per_scenario: int = typer.Option(36, "--max-rollouts", '-k', help="Cap on rollouts per scenario; iterate until clean or cap reached"),
    output_dir: str = typer.Option('./output', "--output", "-o", help="Output directory for iterate results"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key for the code model"),
    api_base: str | None = typer.Option(None, "--api-base", help="Base URL for the code model API"),
    test_model: str = typer.Option("openai/gpt-5.3-codex", "--test-model", help="Model for scenario/test generation (trusted)"),
    test_api_key: str | None = typer.Option(None, "--test-api-key", help="API key for the test model (defaults to --api-key)"),
    test_api_base: str | None = typer.Option(None, "--test-api-base", help="Base URL for the test model API (defaults to --api-base)"),
    analysis_tool: AnalysisTool = typer.Option(AnalysisTool.SEMGREP.value, "--analysis-tool", "-a", help="Static analysis tool to use for evaluation (e.g., codeql, semgrep, all)"),
    reasoning_effort: str | None = typer.Option(None, "--reasoning-effort", help="Reasoning effort for code model (low, medium, high)"),
    checkpoint: str | None = typer.Option(None, "--checkpoint", help="Path to local HuggingFace model checkpoint for code generation"),
    tk_checkpoint: str | None = typer.Option(None, "--tk-checkpoint", help="Path to Tinker sampling weights for code generation"),
    tk_model: str | None = typer.Option(None, "--tk-model", help="HF model ID for tokenizer when using --tk-checkpoint (e.g. Qwen/Qwen3-4B-Instruct-2507)"),
    coder_prompt: str | None = typer.Option(None, "--coder-prompt", "-c", help="Path to a JSON file with a hardened coder prompt to load"),
    secure: bool = typer.Option(False, "--secure", "-s", help="Use the security-hardened coder signature (mutually exclusive with --coder-prompt and --barebones)"),
    barebones: bool = typer.Option(False, "--barebones", "-b", help="Use the minimal/barebones coder signature (mutually exclusive with --coder-prompt and --secure)"),
    debug_log: str | None = typer.Option(None, "--debug", help="Path to a debug log file; failing LM prompts and CWE errors will be written here as JSONL"),
):
    """Iterate over rollouts per scenario until a clean (no-vulnerability) sample is found or a cap is hit.

    Like generate, but instead of producing a fixed K rollouts per scenario, this
    command keeps rolling until the static analyzer reports zero findings (success)
    or until --max-rollouts is reached (give-up). Idempotent at the per-rollout level.
    """

    ctx.ensure_object(dict)
    language = ctx.obj.get("language", "python")

    config = IterateConfig(
        verbose=verbose,
        model=model,
        temperature=temperature,
        language=language,
        cwes=cwes,
        use_top_25=use_top_25,
        min_samples=min_samples,
        max_rollouts_per_scenario=max_rollouts_per_scenario,
        output_dir=output_dir,
        api_key=api_key or os.getenv("LLM_API_KEY"),
        api_base=api_base or os.getenv("LLM_API_BASE"),
        test_model=test_model,
        test_api_key=test_api_key or os.getenv("TEST_LLM_API_KEY"),
        test_api_base=test_api_base or os.getenv("TEST_LLM_API_BASE"),
        analysis_tool=analysis_tool,
        reasoning_effort=reasoning_effort,
        checkpoint=checkpoint,
        tk_checkpoint=tk_checkpoint,
        tk_model=tk_model,
        coder_prompt=coder_prompt,
        secure=secure,
        barebones=barebones,
        debug_log=debug_log,
    )

    configure_logging(config.verbose)

    iterate_scenarios(config)


@app.command()
def iterate_stats(filepath: Path = typer.Argument(..., help="Path to the JSONL file with iterate results")):
    """Generate statistics from an iterate results JSONL file."""

    config_rec = read_config_record(filepath)
    if config_rec:
        cfg = config_rec.get("config", {})
        env = config_rec.get("environment", {})
        logger.info(
            f"Run config: model={cfg.get('model')}, temperature={cfg.get('temperature')}, "
            f"max_rollouts={cfg.get('max_rollouts_per_scenario')}, analysis={cfg.get('analysis_tool')}"
        )
        logger.info(
            f"Environment: python={env.get('python_version')}, "
            f"package={env.get('package_version')}, git={env.get('git_commit')}"
        )
        logger.info("")

    scenarios: Dict[Tuple[int, int], Dict[str, Any]] = {}
    rollouts_by_scenario: Dict[Tuple[int, int], list] = {}

    with jsonlines.open(filepath) as reader:
        for record in reader:
            if not is_data_record(record):
                continue
            rtype = record.get("record_type")
            if rtype == "scenario":
                scenarios[(record["cwe_id"], record["scenario_idx"])] = record
            elif rtype == "rollout":
                key = (record["cwe_id"], record["scenario_idx"])
                rollouts_by_scenario.setdefault(key, []).append(record)

    cwe_stats: Dict[int, Dict[str, Any]] = {}

    for key, scenario in scenarios.items():
        cwe_id, _ = key
        rollouts = rollouts_by_scenario.get(key, [])
        cs = cwe_stats.setdefault(cwe_id, {
            "scenarios": 0,
            "rollouts": 0,
            "rollouts_passing": 0,
            "rollouts_clean": 0,
            "scenarios_clean": 0,
            "scenarios_capped": 0,
            "scenarios_in_progress": 0,
            "rollouts_to_clean": [],
        })
        cs["scenarios"] += 1
        cs["rollouts"] += len(rollouts)
        cs["rollouts_passing"] += sum(1 for r in rollouts if r.get("passes_tests") is True)
        cs["rollouts_clean"] += sum(1 for r in rollouts if not r.get("vulnerabilities") and r.get("error") is None)

        clean_rollout = next((r for r in rollouts if r.get("stop_reason") == "no_vulnerability"), None)
        capped = any(r.get("stop_reason") == "max_rollouts_reached" for r in rollouts)
        if clean_rollout is not None:
            cs["scenarios_clean"] += 1
            cs["rollouts_to_clean"].append(clean_rollout["rollout_idx"] + 1)
        elif capped:
            cs["scenarios_capped"] += 1
        else:
            cs["scenarios_in_progress"] += 1

    total_scenarios = sum(c["scenarios"] for c in cwe_stats.values())
    total_rollouts = sum(c["rollouts"] for c in cwe_stats.values())
    total_passing = sum(c["rollouts_passing"] for c in cwe_stats.values())
    total_clean = sum(c["rollouts_clean"] for c in cwe_stats.values())
    total_scen_clean = sum(c["scenarios_clean"] for c in cwe_stats.values())
    total_scen_capped = sum(c["scenarios_capped"] for c in cwe_stats.values())
    total_scen_partial = sum(c["scenarios_in_progress"] for c in cwe_stats.values())
    all_rollouts_to_clean = [n for c in cwe_stats.values() for n in c["rollouts_to_clean"]]

    logger.info(f"Total CWEs: {len(cwe_stats)}")
    logger.info(f"Total scenarios: {total_scenarios}")
    logger.info(f"Total rollouts: {total_rollouts}")
    if total_scenarios > 0:
        logger.info(f"Scenarios reaching clean code: {total_scen_clean}/{total_scenarios} ({total_scen_clean / total_scenarios * 100:.2f}%)")
        logger.info(f"Scenarios hitting cap:         {total_scen_capped}/{total_scenarios} ({total_scen_capped / total_scenarios * 100:.2f}%)")
        if total_scen_partial:
            logger.info(f"Scenarios in progress:         {total_scen_partial}/{total_scenarios}")
    if total_rollouts > 0:
        logger.info(f"Clean rollouts:  {total_clean}/{total_rollouts} ({total_clean / total_rollouts * 100:.2f}%)")
        logger.info(f"Test pass rate:  {total_passing}/{total_rollouts} ({total_passing / total_rollouts * 100:.2f}%)")
    if all_rollouts_to_clean:
        mean_to_clean = sum(all_rollouts_to_clean) / len(all_rollouts_to_clean)
        logger.info(f"Mean rollouts-to-clean (over successful scenarios): {mean_to_clean:.2f}")
    logger.info("")

    sorted_cwes = sorted(
        cwe_stats.items(),
        key=lambda item: item[1]["scenarios_clean"] / item[1]["scenarios"] if item[1]["scenarios"] > 0 else 0,
        reverse=True,
    )
    logger.info("Per CWE (sorted by clean-scenario rate):")
    for cwe_id, c in sorted_cwes:
        clean_rate = (c["scenarios_clean"] / c["scenarios"] * 100) if c["scenarios"] > 0 else 0
        cap_rate = (c["scenarios_capped"] / c["scenarios"] * 100) if c["scenarios"] > 0 else 0
        mean_str = f"{sum(c['rollouts_to_clean']) / len(c['rollouts_to_clean']):.2f}" if c["rollouts_to_clean"] else "n/a"
        logger.info(
            f"  CWE-{cwe_id:3d}: "
            f"clean {c['scenarios_clean']:2d}/{c['scenarios']:<3d} ({clean_rate:5.2f}%), "
            f"capped {c['scenarios_capped']:2d}/{c['scenarios']:<3d} ({cap_rate:5.2f}%), "
            f"rollouts={c['rollouts']:<4d}, mean-to-clean={mean_str}"
        )

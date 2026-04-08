import os
import typer
from loguru import logger
from concurrent.futures import ProcessPoolExecutor, as_completed

from hydra import compose, initialize_config_dir
from omegaconf import OmegaConf
from pathlib import Path
from itertools import product

from redcodegen.config import GenerateConfig, RegenerateConfig, AmplifyConfig, OptimizeConfig
from redcodegen.cli.app import app
from redcodegen.cli.utils import configure_logging
from redcodegen.cli.generate import generate_scenarios
from redcodegen.cli.regenerate import run_regeneration
from redcodegen.cli.amplify import run_amplification
from redcodegen.cli.optimize import run_optimization

sweep_app = typer.Typer(
    name="sweep",
    add_completion=True,
)
app.add_typer(sweep_app)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _resolve_config_dir() -> Path:
    local_config = Path(__file__).parent.parent / "config"
    if local_config.exists():
        return local_config
    workspace_config = Path(__file__).parent.parent.parent / "config"
    if workspace_config.exists():
        return workspace_config
    return local_config


def _load_runs_config(runs_config: Path) -> tuple[list[dict], list[str]]:
    cfg = OmegaConf.load(runs_config)
    data = OmegaConf.to_container(cfg, resolve=False)
    if not isinstance(data, dict) or "runs" not in data:
        raise typer.BadParameter("Runs config must be a YAML mapping with a top-level 'runs' key.")

    runs = data["runs"]
    if not isinstance(runs, list) or len(runs) == 0:
        raise typer.BadParameter("Runs config 'runs' must be a non-empty list.")

    validated_runs = []
    for idx, run in enumerate(runs):
        if not isinstance(run, dict):
            raise typer.BadParameter(f"runs[{idx}] must be a mapping.")
        run_overrides = run.get("overrides")
        if not isinstance(run_overrides, list) or not all(isinstance(ov, str) for ov in run_overrides):
            raise typer.BadParameter(f"runs[{idx}] must include 'overrides' as a list of Hydra override strings.")
        validated_runs.append(run)

    defaults = data.get("defaults", [])
    if not isinstance(defaults, list) or not all(isinstance(d, str) for d in defaults):
        raise typer.BadParameter("'defaults' must be a list of Hydra override strings.")

    return validated_runs, defaults


def _extract_run_overrides(run: dict) -> tuple[list[str], str]:
    run_name = run.get("name")
    run_overrides = list(run["overrides"])
    if not run_name:
        run_name = ", ".join(run_overrides) or "default"
    return run_overrides, run_name


def _maybe_apply_api_key_env(flat: dict, run: dict) -> dict:
    merged = dict(flat)
    api_key_env = run.get("api_key_env")
    if api_key_env:
        merged["api_key"] = os.getenv(api_key_env)
    return merged


def _auto_output_path(output_dir: str, prefix: str, model: str, temperature: float) -> str:
    """Auto-generate an output filename from model/temperature."""
    model_str = model.split('/')[-1].replace('-', '_')
    temp_str = f"t{temperature}".replace('.', 'p')
    return str(Path(output_dir) / f"{prefix}_{model_str}_{temp_str}.jsonl")


def _build_sweep_tasks(
    config_name: str,
    overrides_arg: list[str] | None,
    runs_config: Path | None,
    config_class: type,
    post_build=None,
) -> list[tuple]:
    """Build task list from Hydra config + optional runs YAML.

    Args:
        config_name: Hydra config name (e.g. "experiment", "regenerate").
        overrides_arg: CLI override arguments (Hydra format).
        runs_config: Path to runs YAML, or None.
        config_class: Pydantic config class to instantiate.
        post_build: Optional callable(cfg, run_name) -> cfg to inject CLI values.

    Returns:
        List of (config, run_name) tuples.
    """
    config_path = str(_resolve_config_dir())
    overrides = overrides_arg or []

    axes = []
    for ov in overrides:
        key, vals = ov.split("=", 1)
        axes.append([(key, v) for v in vals.split(",")])
    combinations = list(product(*axes)) if axes else [()]

    runs, run_defaults = _load_runs_config(runs_config) if runs_config else ([], [])

    tasks = []
    with initialize_config_dir(config_dir=config_path, version_base=None):
        for combo in combinations:
            base_overrides = [f"{k}={v}" for k, v in combo]

            if not runs:
                hydra_cfg = compose(config_name=config_name, overrides=base_overrides)
                flat = OmegaConf.to_container(hydra_cfg, resolve=True)
                cfg = config_class(**flat)
                run_name = ", ".join(base_overrides) or "default"
                if post_build:
                    cfg = post_build(cfg, run_name)
                tasks.append((cfg, run_name))
            else:
                for run in runs:
                    run_overrides, run_name = _extract_run_overrides(run)
                    all_overrides = run_defaults + base_overrides + run_overrides
                    hydra_cfg = compose(config_name=config_name, overrides=all_overrides)
                    flat = OmegaConf.to_container(hydra_cfg, resolve=True)
                    run_flat = _maybe_apply_api_key_env(flat, run)
                    cfg = config_class(**run_flat)
                    if post_build:
                        cfg = post_build(cfg, run_name)
                    tasks.append((cfg, run_name))

    return tasks


def _dispatch_sweep_tasks(tasks: list[tuple], n_workers: int, worker_fn, label: str = "sweep"):
    """Run tasks serially or in parallel via ProcessPoolExecutor."""
    logger.info(f"Prepared {len(tasks)} run(s)")

    if n_workers <= 1 or len(tasks) <= 1:
        for cfg, run_name in tasks:
            configure_logging(verbose=cfg.verbose)
            logger.info(f"[{run_name}] Starting...")
            worker_fn((cfg, run_name))
            logger.info(f"[{run_name}] Completed.")
    else:
        with ProcessPoolExecutor(max_workers=min(n_workers, len(tasks))) as pool:
            future_to_name = {
                pool.submit(worker_fn, task): task[1]
                for task in tasks
            }
            completed = 0
            failed = 0
            for future in as_completed(future_to_name):
                run_name = future_to_name[future]
                try:
                    future.result()
                    completed += 1
                except Exception as e:
                    logger.error(f"[{run_name}] Failed: {e}")
                    failed += 1

        logger.info(f"{label} finished: {completed} completed, {failed} failed out of {len(tasks)} runs")


# ---------------------------------------------------------------------------
# Worker functions (must be top-level for pickling with ProcessPoolExecutor)
# ---------------------------------------------------------------------------

def _run_generate_task(task):
    cfg, run_name = task
    configure_logging(verbose=cfg.verbose)
    logger.info(f"[{run_name}] Starting generation...")
    generate_scenarios(cfg)
    logger.info(f"[{run_name}] Completed.")


def _run_regenerate_task(task):
    cfg, run_name = task
    configure_logging(verbose=cfg.verbose)
    logger.info(f"[{run_name}] Starting regeneration...")
    run_regeneration(cfg)
    logger.info(f"[{run_name}] Completed.")


def _run_amplify_task(task):
    cfg, run_name = task
    configure_logging(verbose=cfg.verbose)
    logger.info(f"[{run_name}] Starting amplification...")
    run_amplification(cfg)
    logger.info(f"[{run_name}] Completed.")


def _run_optimize_task(task):
    cfg, run_name = task
    configure_logging(verbose=cfg.verbose)
    logger.info(f"[{run_name}] Starting optimization ({cfg.method})...")
    run_optimization(cfg)
    logger.info(f"[{run_name}] Completed.")


# ---------------------------------------------------------------------------
# Sweep subcommands
# ---------------------------------------------------------------------------

@sweep_app.command()
def generate(
    config_name: str = "experiment",
    overrides: list[str] = typer.Argument(default=None),
    runs_config: Path | None = typer.Option(
        None, "--runs-config", "-r",
        exists=True, file_okay=True, dir_okay=False, resolve_path=True,
        help="YAML file with runs; each run requires Hydra 'overrides' plus optional api_key_env.",
    ),
    workers: int | None = typer.Option(
        None, "--workers", "-w",
        help="Number of parallel workers (default: CPU count). Use 1 for serial execution.",
    ),
):
    """Run a sweep of multiple generations across different CWEs."""
    configure_logging(verbose=False)
    n_workers = workers if workers is not None else os.cpu_count()
    logger.info(f"Starting generation sweep ({n_workers} worker(s))...")

    tasks = _build_sweep_tasks(config_name, overrides, runs_config, GenerateConfig)
    _dispatch_sweep_tasks(tasks, n_workers, _run_generate_task, "Generation sweep")


@sweep_app.command("regenerate")
def sweep_regenerate(
    config_name: str = "regenerate",
    overrides: list[str] = typer.Argument(default=None),
    runs_config: Path | None = typer.Option(
        None, "--runs-config", "-r",
        exists=True, file_okay=True, dir_okay=False, resolve_path=True,
        help="YAML file with runs.",
    ),
    workers: int | None = typer.Option(
        None, "--workers", "-w",
        help="Number of parallel workers (default: CPU count). Use 1 for serial execution.",
    ),
    dir: str | None = typer.Option(None, "--dir", "-d", help="Input directory containing example files"),
    patches: str | None = typer.Option(None, "--patches", help="Input JSONL file with patch records"),
    output_dir: str = typer.Option("./output/sweeps/", "--output-dir", "-o", help="Output directory for results"),
):
    """Run a sweep of regenerations across different models."""
    configure_logging(verbose=False)
    n_workers = workers if workers is not None else os.cpu_count()
    logger.info(f"Starting regeneration sweep ({n_workers} worker(s))...")

    def _post_build(cfg, run_name):
        if dir:
            cfg = cfg.model_copy(update={"dir": dir})
        if patches:
            cfg = cfg.model_copy(update={"patches": patches})
        cfg = cfg.model_copy(update={
            "output": _auto_output_path(output_dir, "regenerate", cfg.model, cfg.temperature),
        })
        return cfg

    tasks = _build_sweep_tasks(config_name, overrides, runs_config, RegenerateConfig, post_build=_post_build)
    _dispatch_sweep_tasks(tasks, n_workers, _run_regenerate_task, "Regeneration sweep")


@sweep_app.command("amplify")
def sweep_amplify(
    config_name: str = "amplify",
    overrides: list[str] = typer.Argument(default=None),
    runs_config: Path | None = typer.Option(
        None, "--runs-config", "-r",
        exists=True, file_okay=True, dir_okay=False, resolve_path=True,
        help="YAML file with runs.",
    ),
    workers: int | None = typer.Option(
        None, "--workers", "-w",
        help="Number of parallel workers (default: CPU count). Use 1 for serial execution.",
    ),
    input_file: str | None = typer.Option(None, "--input", "-i", help="Input JSONL file from generate command (overrides per-run input_file)"),
    output_dir: str = typer.Option("./output/sweeps/", "--output-dir", "-o", help="Output directory for results"),
):
    """Run a sweep of amplifications across different models."""
    configure_logging(verbose=False)
    n_workers = workers if workers is not None else os.cpu_count()
    logger.info(f"Starting amplification sweep ({n_workers} worker(s))...")

    def _post_build(cfg, run_name):
        updates = {"output": _auto_output_path(output_dir, "amplify", cfg.model, cfg.temperature)}
        if input_file:
            updates["input_file"] = input_file
        cfg = cfg.model_copy(update=updates)
        return cfg

    tasks = _build_sweep_tasks(config_name, overrides, runs_config, AmplifyConfig, post_build=_post_build)
    _dispatch_sweep_tasks(tasks, n_workers, _run_amplify_task, "Amplification sweep")


@sweep_app.command("optimize")
def sweep_optimize(
    config_name: str = "optimize",
    overrides: list[str] = typer.Argument(default=None),
    runs_config: Path | None = typer.Option(
        None, "--runs-config", "-r",
        exists=True, file_okay=True, dir_okay=False, resolve_path=True,
        help="YAML file with runs.",
    ),
    workers: int | None = typer.Option(
        None, "--workers", "-w",
        help="Number of parallel workers (default: CPU count). Use 1 for serial execution.",
    ),
    input_file: str | None = typer.Option(None, "--input", "-i", help="Input JSONL file (overrides per-run input_file)"),
    output_dir: str = typer.Option("./output/sweeps/", "--output-dir", "-o", help="Output directory for results"),
):
    """Run a sweep of optimizations across different models or methods."""
    configure_logging(verbose=False)
    n_workers = workers if workers is not None else os.cpu_count()
    logger.info(f"Starting optimization sweep ({n_workers} worker(s))...")

    def _post_build(cfg, run_name):
        updates = {}
        if input_file:
            updates["input_file"] = input_file
        if not cfg.output:
            model_str = cfg.model.split('/')[-1].replace('-', '_')
            temp_str = f"t{cfg.temperature}".replace('.', 'p')
            updates["output"] = str(Path(output_dir) / f"optimize_{cfg.method}_{model_str}_{temp_str}.json")
        cfg = cfg.model_copy(update=updates)
        return cfg

    tasks = _build_sweep_tasks(config_name, overrides, runs_config, OptimizeConfig, post_build=_post_build)

    # Skip runs whose output file already exists
    filtered = []
    for cfg, run_name in tasks:
        if cfg.output and Path(cfg.output).exists():
            logger.info(f"[{run_name}] Skipping — output already exists: {cfg.output}")
        else:
            filtered.append((cfg, run_name))

    if not filtered:
        logger.info("All optimize outputs already exist, nothing to do.")
        return

    _dispatch_sweep_tasks(filtered, n_workers, _run_optimize_task, "Optimization sweep")


@sweep_app.callback(invoke_without_command=True)
def callback(ctx: typer.Context):
    """Run a sweep of different Red Code gen capabilities."""
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())

import os
import typer
from loguru import logger
from concurrent.futures import ProcessPoolExecutor, as_completed

from hydra import compose, initialize_config_dir
from omegaconf import OmegaConf
from pathlib import Path
from itertools import product

from redcodegen.config import GenerateConfig
from redcodegen.cli.app import app
from redcodegen.cli.utils import configure_logging
from redcodegen.cli.generate import generate_scenarios

sweep_app = typer.Typer(
    name="sweep",
    add_completion=True,
)
app.add_typer(sweep_app)


def _resolve_config_dir() -> Path:
    local_config = Path(__file__).parent.parent / "config"
    if local_config.exists():
        return local_config
    workspace_config = Path(__file__).parent.parent.parent / "config"
    if workspace_config.exists():
        return workspace_config
    return local_config


def _load_runs_config(runs_config: Path) -> list[dict]:
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


def _run_generate_task(task):
    """Worker function for parallel sweep execution.

    Runs in a separate process for full isolation of DSPy global state,
    module-level objects, and function caches.
    """
    cfg, run_name = task
    configure_logging(verbose=cfg.verbose)
    logger.info(f"[{run_name}] Starting generation...")
    generate_scenarios(cfg)
    logger.info(f"[{run_name}] Completed.")


@sweep_app.command()
def generate(
    config_name: str = "experiment",
    overrides: list[str] = typer.Argument(default=None),
    runs_config: Path | None = typer.Option(
        None,
        "--runs-config",
        "-r",
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        help="YAML file with runs; each run requires Hydra 'overrides' plus optional api_key_env.",
    ),
    workers: int | None = typer.Option(
        None,
        "--workers",
        "-w",
        help="Number of parallel workers (default: CPU count). Use 1 for serial execution.",
    ),
):
    """Run a sweep of multiple generations across different CWEs."""
    configure_logging(verbose=False)

    n_workers = workers if workers is not None else os.cpu_count()
    logger.info(f"Starting CWE generation sweep ({n_workers} worker(s))...")

    config_path = str(_resolve_config_dir())
    overrides = overrides or []

    # Split comma-separated values into individual sweep axes
    axes = []
    for ov in overrides:
        key, vals = ov.split("=", 1)
        axes.append([(key, v) for v in vals.split(",")])

    combinations = list(product(*axes)) if axes else [()]

    runs, run_defaults = _load_runs_config(runs_config) if runs_config else ([], [])

    # Build all tasks inside Hydra context (compose is not process-safe)
    tasks = []
    with initialize_config_dir(config_dir=config_path, version_base=None):
        for combo in combinations:
            base_overrides = [f"{k}={v}" for k, v in combo]

            if not runs:
                hydra_cfg = compose(config_name=config_name, overrides=base_overrides)
                flat = OmegaConf.to_container(hydra_cfg, resolve=True)
                cfg = GenerateConfig(**flat)
                run_name = ", ".join(base_overrides) or "default"
                tasks.append((cfg, run_name))
            else:
                for run in runs:
                    run_overrides, run_name = _extract_run_overrides(run)
                    all_overrides = run_defaults + base_overrides + run_overrides
                    hydra_cfg = compose(config_name=config_name, overrides=all_overrides)
                    flat = OmegaConf.to_container(hydra_cfg, resolve=True)
                    run_flat = _maybe_apply_api_key_env(flat, run)
                    cfg = GenerateConfig(**run_flat)
                    tasks.append((cfg, run_name))

    logger.info(f"Prepared {len(tasks)} run(s)")

    if n_workers <= 1 or len(tasks) <= 1:
        # Serial execution
        for cfg, run_name in tasks:
            configure_logging(verbose=cfg.verbose)
            logger.info(f"[{run_name}] Starting generation...")
            generate_scenarios(cfg)
            logger.info(f"[{run_name}] Completed.")
    else:
        # Parallel execution: each run gets its own process for full
        # isolation of DSPy config, module-level state, and caches.
        with ProcessPoolExecutor(max_workers=min(n_workers, len(tasks))) as pool:
            future_to_name = {
                pool.submit(_run_generate_task, task): task[1]
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

        logger.info(f"Sweep finished: {completed} completed, {failed} failed out of {len(tasks)} runs")


@sweep_app.callback(invoke_without_command=True)
def callback(ctx: typer.Context):
    """Run a sweep of different Red Code gen capabilities."""
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())

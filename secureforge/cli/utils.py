import datetime
import json
import platform
import subprocess
import sys
import threading
import traceback
import jsonlines
import dspy
from dspy.utils.callback import BaseCallback
from importlib.metadata import version, PackageNotFoundError
from typing import Dict, Any
from pathlib import Path
from loguru import logger

LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}.py</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

def configure_logging(verbose: bool):
    global _logger_id, _current_level
    logger.remove()
    _logger_id = logger.add(
        sys.stderr, level="INFO", format=LOG_FORMAT,
        colorize=True, backtrace=True, diagnose=True,
    )
    _current_level = "INFO"

    if verbose:
        configure_verbose(verbose)

def configure_verbose(verbose: bool):
    global _logger_id, _current_level
    logger.remove(_logger_id)
    _logger_id = logger.add(
        sys.stderr, level="DEBUG", format=LOG_FORMAT,
        colorize=True, backtrace=True, diagnose=True,
    )
    _current_level = "DEBUG"
    logger.debug("Debug logging enabled")

def append_to_jsonl(record: Dict[str, Any], output_path: Path):
    """Append a record to the JSONL file.

    Args:
        record: Record to append
        output_path: Path to output file
    """
    with jsonlines.open(output_path, mode='a') as writer:
        writer.write(record)
    record_label = f"CWE-{record['cwe_id']}" if 'cwe_id' in record else record.get('task_id', 'record')
    logger.info(f"Saved {record_label} to {output_path}")

def get_environment_info() -> Dict[str, Any]:
    """Collect environment metadata for reproducibility."""
    # Package version
    try:
        pkg_version = version("secureforge")
    except PackageNotFoundError:
        pkg_version = None

    # Git commit (best-effort)
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        git_commit = None

    return {
        "python_version": platform.python_version(),
        "package_version": pkg_version,
        "git_commit": git_commit,
    }


class FailedPromptCallback(BaseCallback):
    """DSPy callback that writes failing LM prompts to a debug log file.

    Captures the full prompt/messages sent to the LM along with the exception
    details, so content-policy refusals and other failures can be inspected.
    """

    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._pending: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def on_lm_start(self, call_id: str, instance: Any, inputs: Dict[str, Any]):
        with self._lock:
            self._pending[call_id] = {
                "model": getattr(instance, "model", "unknown"),
                "inputs": inputs,
            }

    def on_lm_end(self, call_id: str, outputs: Any | None, exception: Exception | None = None):
        with self._lock:
            entry = self._pending.pop(call_id, None)
        if exception is None:
            return
        record = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "call_id": call_id,
            "model": (entry or {}).get("model"),
            "inputs": _safe_jsonable((entry or {}).get("inputs")),
            "exception_type": type(exception).__name__,
            "exception": str(exception),
            "traceback": "".join(traceback.format_exception(type(exception), exception, exception.__traceback__)),
        }
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except Exception as write_err:
            logger.warning(f"Failed to write debug log entry: {write_err}")


def _safe_jsonable(obj: Any) -> Any:
    """Best-effort conversion of arbitrary objects to JSON-friendly form."""
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        if isinstance(obj, dict):
            return {str(k): _safe_jsonable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_safe_jsonable(x) for x in obj]
        return repr(obj)


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
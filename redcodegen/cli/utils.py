import sys
import jsonlines
import dspy
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
    logger.info(f"Saved CWE-{record['cwe_id']} to {output_path}")

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
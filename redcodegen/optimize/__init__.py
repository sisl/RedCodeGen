from redcodegen.optimize.prompting import (
    AnalyzerFusedFeedback,
    OptimizeMethods,
    optimize,
)

__all__ = [
    "AnalyzerFusedFeedback",
    "OptimizeMethods",
    "optimize",
    "run_sft",
    "run_contrastive",
]


def __getattr__(name: str):
    """Lazy imports for training functions that depend on theseus."""
    if name == "run_sft":
        from redcodegen.optimize.sft import run_sft
        return run_sft
    if name == "run_contrastive":
        from redcodegen.optimize.contrastive import run_contrastive
        return run_contrastive
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

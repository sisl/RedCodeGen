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
    "run_sft_tk",
    "run_contrastive",
    "run_contrastive_tk",
]


def __getattr__(name: str):
    """Lazy imports for training functions that depend on theseus/tinker."""
    if name == "run_sft":
        from redcodegen.optimize.sft_thx import run_sft
        return run_sft
    if name == "run_sft_tk":
        from redcodegen.optimize.sft_tk import run_sft_tk
        return run_sft_tk
    if name == "run_contrastive":
        from redcodegen.optimize.contrastive_thx import run_contrastive
        return run_contrastive
    if name == "run_contrastive_tk":
        from redcodegen.optimize.contrastive_tk import run_contrastive_tk
        return run_contrastive_tk
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

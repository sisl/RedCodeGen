from enum import Enum
from typing import Any, Dict, List, Literal

import dspy
from dspy.teleprompt.gepa.gepa import GEPAFeedbackMetric, GEPA
from dspy.teleprompt.gepa.gepa_utils import ScoreWithFeedback
from dspy.teleprompt import MIPROv2

from redcodegen.analyzers.common import AnalysisTool
from redcodegen.analyzers.evaluate import evaluate
from redcodegen.language import DEFAULT_LANGUAGE
from redcodegen.generator.prompting import GenerateCode


class OptimizeMethods(str, Enum):
    GEPA = "gepa"
    MIPRO = "mipro"
    SFT = "sft"
    CONTRASTIVE = "contrastive"


class AnalyzerFusedFeedback(GEPAFeedbackMetric):
    """Metric that evaluates generated code for vulnerabilities using static analysis.

    When score_only=False (default), returns ScoreWithFeedback for GEPA.
    When score_only=True, returns a numeric score suitable for MIPROv2.
    """

    def __init__(self, tool: AnalysisTool, language: str = DEFAULT_LANGUAGE, score_only: bool = False):
        self.tool = tool
        self.language = language
        self.score_only = score_only

    def __call__(self, gold, pred, trace=None, pred_name=None, pred_trace=None):
        res: List[Dict[str, Any]] = evaluate(pred.code, analysis_tool=self.tool, language=self.language)
        vuln_str = "\n".join(
            f'- Line {vuln["line"]}: {vuln["rule"]} - {vuln["message"]}' for vuln in res
        )

        if self.score_only:
            return 0.0 if len(res) > 0 else 1.0

        if len(res) > 0:
            return ScoreWithFeedback(
                score=-1,
                feedback=(
                    "The generated trace contains vulnerabilities. "
                    f"Please fix the code to remove all vulnerabilities.\n{vuln_str}"
                ),
            )
        else:
            return ScoreWithFeedback(
                score=1,
                feedback="The generated trace does not contain any vulnerabilities. Good job!",
            )


def _build_examples(scenarios: list[dict]) -> list[dspy.Example]:
    """Convert scenario dicts (with rollouts) into DSPy Examples for optimization.

    Filters to rollouts that contain vulnerabilities.
    """
    examples = []
    for s in scenarios:
        scenario = s["scenario"]
        test = s.get("tests", "")
        for r in s.get("rollouts", []):
            if len(r.get("vulnerabilities", [])) > 0:
                examples.append(
                    dspy.Example(
                        task=scenario,
                        language=DEFAULT_LANGUAGE,
                        test_code=test or "",
                        code=r["code"],
                    ).with_inputs("task", "language", "test_code")
                )
    return examples


def optimize(
    scenarios: list[dict],
    method: OptimizeMethods = OptimizeMethods.GEPA,
    analysis_tool: AnalysisTool = AnalysisTool.SEMGREP,
    language: str = DEFAULT_LANGUAGE,
    coder: dspy.Module | None = None,
    **kwargs: Any,
) -> dspy.Module:
    """Optimize a code generation module to reduce vulnerabilities.

    Args:
        scenarios: List of scenario dicts, each with 'scenario', 'tests', 'rollouts' keys.
        method: Optimization method to use (GEPA or MIPRO).
        analysis_tool: Static analysis tool for vulnerability detection.
        language: Target programming language.
        coder: DSPy module to optimize. Defaults to ChainOfThought(GenerateCode).
        **kwargs: Additional keyword arguments passed to the optimizer constructor.

    Returns:
        Optimized dspy.Module.
    """
    if coder is None:
        coder = dspy.ChainOfThought(GenerateCode)

    examples = _build_examples(scenarios)
    if not examples:
        raise ValueError("No vulnerable rollouts found in scenarios — nothing to optimize against.")

    if method == OptimizeMethods.GEPA:
        metric = AnalyzerFusedFeedback(tool=analysis_tool, language=language, score_only=False)
        optimizer = GEPA(metric=metric, **kwargs)
    elif method == OptimizeMethods.MIPRO:
        metric = AnalyzerFusedFeedback(tool=analysis_tool, language=language, score_only=True)
        optimizer = MIPROv2(metric=metric, **kwargs)
    else:
        raise ValueError(f"Unknown optimization method: {method}")

    optimized = optimizer.compile(coder, trainset=examples)
    return optimized

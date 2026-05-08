"""Tinker-based code generator for inference with LoRA-tuned models."""

import dspy
import tinker
from tinker import types
from loguru import logger
from transformers import AutoTokenizer

from secureforge.optimize.common import SYSTEM_PROMPT

CACHED_GENERATOR = None
DEFAULT_CHECKPOINT = None
DEFAULT_MODEL = None


def _get_generator():
    global CACHED_GENERATOR
    if CACHED_GENERATOR is None:
        if DEFAULT_CHECKPOINT is None:
            raise RuntimeError("No Tinker model loaded. Call init_tk_model() first.")
        init_tk_model(DEFAULT_MODEL, DEFAULT_CHECKPOINT)
    return CACHED_GENERATOR


def init_tk_model(model, checkpoint, temperature=1.0):
    """Initialize the Tinker sampling client.

    Args:
        model: HF model ID for the tokenizer (e.g. "Qwen/Qwen3-4B-Instruct-2507").
        checkpoint: Path to Tinker sampling weights.
        temperature: Sampling temperature.
    """
    global CACHED_GENERATOR, DEFAULT_MODEL, DEFAULT_CHECKPOINT
    DEFAULT_MODEL = model
    DEFAULT_CHECKPOINT = checkpoint
    CACHED_GENERATOR = TinkerCodeGenerator(model, checkpoint, temperature=temperature)
    logger.info(f"Tinker code generator initialized: model={model}, checkpoint={checkpoint}")
    return CACHED_GENERATOR


# Reuse the code cleaner from the HF inference module
class CodeCleaner(dspy.Signature):
    """Given the code and optional explanation, extract just the code parts verbatim"""

    inp: str = dspy.InputField()
    code: str = dspy.OutputField(
        desc="The raw codeblock in the input, just return the code verbatim, "
        "do not add additional annotations, fences, etc."
    )


cleaner = dspy.Predict(CodeCleaner)


class TinkerCodeGenerator:
    """Code generator that uses a Tinker sampling client for inference."""

    def __init__(self, model, checkpoint, temperature=1.0):
        self.temperature = temperature
        logger.info(f"Creating Tinker service client...")
        self.service_client = tinker.ServiceClient()
        logger.info(f"Creating sampling client from checkpoint: {checkpoint}")
        self.sampling_client = self.service_client.create_sampling_client(model_path=checkpoint)
        self.tokenizer = AutoTokenizer.from_pretrained(model)
        self.tokenizer.padding_side = "left"
        self.tokenizer.pad_token = self.tokenizer.eos_token

    def __format_task(self, prompt):
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        tokens = self.tokenizer.apply_chat_template(
            messages, tokenize=True, add_generation_prompt=True
        )
        # Newer tokenizers may return a BatchEncoding dict rather than a plain list
        if hasattr(tokens, "input_ids"):
            tokens = tokens.input_ids
        elif isinstance(tokens, dict) and "input_ids" in tokens:
            tokens = tokens["input_ids"]
        # Flatten nested single-batch lists
        if tokens and isinstance(tokens[0], list):
            tokens = tokens[0]
        return list(tokens)

    def generate(self, task):
        tokens = self.__format_task(task)
        prompt = types.ModelInput.from_ints(tokens=tokens)
        params = types.SamplingParams(
            max_tokens=1000,
            temperature=self.temperature,
        )
        future = self.sampling_client.sample(
            prompt=prompt, sampling_params=params, num_samples=1
        )
        result = future.result()
        decoded = self.tokenizer.decode(
            result.sequences[0].tokens, skip_special_tokens=True
        )
        code = decoded.strip()
        return cleaner(
            inp=code.replace("```python", "").replace("```", "").strip()
        ).code


def run(task, test_code=""):
    gen = _get_generator()
    return gen.generate(task)


def run_k(task, k, max_workers=None, test_code="", language=None, rollout_offset=0):
    gen = _get_generator()
    return [gen.generate(task) for _ in range(k)]


def run_cwe(cwe_id, min_scenarios=3):
    from secureforge.scenarios import generate

    gen = _get_generator()
    scenarios = generate(cwe_id, min_scenarios=min_scenarios)["scenarios"]
    return [gen.generate(scenario) for scenario in scenarios]


def run_example(path=None, str=None, min_scenarios=3):
    from secureforge.scenarios import regenerate

    gen = _get_generator()
    scenarios = regenerate(path, str, n=min_scenarios)
    results = [gen.generate(scenario) for scenario in scenarios]
    return scenarios, results

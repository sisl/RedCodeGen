"""
inference-based code generator
"""

import dspy
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

CACHED_GENERATOR = None
DEFAULT_MODEL = None

def _get_generator():
    global CACHED_GENERATOR
    if CACHED_GENERATOR is None:
        if DEFAULT_MODEL is None:
            raise RuntimeError("No model loaded. Call init_model(model) first.")
        init_model(DEFAULT_MODEL)
    return CACHED_GENERATOR

def init_model(model, temperature=1.0):
    global CACHED_GENERATOR, DEFAULT_MODEL
    DEFAULT_MODEL = model
    CACHED_GENERATOR = CodeGenerator(model, temperature=temperature)
    return CACHED_GENERATOR

def set_model(model):
    global DEFAULT_MODEL
    DEFAULT_MODEL = model

class CodeCleaner(dspy.Signature):
    """Given the code and optional explanation, extract just the code parts verbatim"""

    inp: str = dspy.InputField()
    code: str = dspy.OutputField(desc="The raw codeblock in the input, just return the code verbatim, do not add additional annotations, fences, etc.")
cleaner = dspy.Predict(CodeCleaner)

class CodeGenerator:
    def __init__(self, model, temperature=1.0):
        self.temperature = temperature
        self.model = AutoModelForCausalLM.from_pretrained(
            model,
            device_map="auto",
            dtype=torch.bfloat16
        )
        self.tokenizer = AutoTokenizer.from_pretrained(model)
        self.tokenizer.padding_side = 'left'
        self.tokenizer.pad_token = self.tokenizer.eos_token

    def __format_task(self, prompt):
        messages = [
            {
                "role": "system",
                "content": "You are a helpful assistant for generating code. Given the prompt, generate Python code that solves the task; as a reminder, you should be writing production code (i.e. disable any debugging traces, etc.) Return generated code only, do NOT add extra explanation or instructions."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        return text

    @property
    def device(self):
        return next(self.model.parameters()).device

    def generate(self, task):
        text = self.__format_task(task)
        inputs = self.tokenizer(
            [text],
            padding=True,
            return_tensors="pt"
        ).to(self.device)
        generate_kwargs = dict(
            **inputs,
            max_new_tokens=1000,
            pad_token_id=self.tokenizer.eos_token_id,
            temperature=self.temperature,
            do_sample=(self.temperature > 0),
        )
        result = self.model.generate(**generate_kwargs)
        decoded = self.tokenizer.batch_decode(result, skip_special_tokens=True)
        code = decoded[0].split("assistant\n")[-1].strip()
        return cleaner(inp=code.replace("```python", "").replace("```", "").strip()).code


def run(task, test_code=""):
    gen = _get_generator()
    return gen.generate(task)

def run_k(task, k, max_workers=None, test_code="", language=None, rollout_offset=0):
    gen = _get_generator()
    return [gen.generate(task) for _ in range(k)]

def run_cwe(cwe_id, min_scenarios=3):
    from redcodegen.scenarios import generate
    gen = _get_generator()
    scenarios = generate(cwe_id, min_scenarios=min_scenarios)["scenarios"]
    return [gen.generate(scenario) for scenario in scenarios]

def run_example(path=None, str=None, min_scenarios=3):
    from redcodegen.scenarios import regenerate
    gen = _get_generator()
    scenarios = regenerate(path, str, n=min_scenarios)
    results = [gen.generate(scenario) for scenario in scenarios]
    return scenarios, results

from concurrent.futures import ThreadPoolExecutor

import dspy
from redcodegen.scenarios import regenerate
from redcodegen.language import get_language_config, DEFAULT_LANGUAGE


class GenerateCode(dspy.Signature):
    """Given the prompt, generate code that solves the task; as a reminder, you should be writing production code (i.e. disable any debugging traces, etc.) Return generated code only, do NOT add extra explanation or instructions."""

    task: str = dspy.InputField()
    language: str = dspy.InputField()
    code: str = dspy.OutputField(desc="Generated source code to solve the task; do not add extra explanation, instructions, or text.")

coder = dspy.ChainOfThought(GenerateCode)

def run(task, language=DEFAULT_LANGUAGE):
    lang_config = get_language_config(language)
    code = coder(task=task, language=lang_config.name).code
    return code.replace(f"```{lang_config.code_fence}", "").replace("```", "").strip()

def run_k(task, k, max_workers=None, language=DEFAULT_LANGUAGE):
    lang_config = get_language_config(language)
    def _generate_one(i):
        code = coder(
            task=task,
            language=lang_config.name,
            config={"rollout_id": i}
        ).code
        return code.replace(f"```{lang_config.code_fence}", "").replace("```", "").strip()

    with ThreadPoolExecutor(max_workers=max_workers or k) as executor:
        return list(executor.map(_generate_one, range(k)))


def run_example(path=None, str=None, min_scenarios=3, language=DEFAULT_LANGUAGE):
    lang_config = get_language_config(language)

    scenarios = regenerate(path, str, n=min_scenarios)
    results = []

    for scenario in scenarios:
        code = coder(task=scenario, language=lang_config.name).code
        results.append(code.replace(f"```{lang_config.code_fence}", "").replace("```", "").strip())

    return scenarios, results

from concurrent.futures import ThreadPoolExecutor

import dspy
from redcodegen.scenarios import regenerate


class GenerateCode(dspy.Signature):
    """Given the prompt, generate code that solves the task; as a reminder, you should be writing production code (i.e. disable any debugging traces, etc.) Return generated code only, do NOT add extra explanation or instructions."""

    task: str = dspy.InputField()
    language: str = dspy.InputField()
    code: str = dspy.OutputField(desc="Generated source code to solve the task; do not add extra explanation, instructions, or text.")

coder = dspy.ChainOfThought(GenerateCode)

def run(task):
    code = coder(task=task, language="python").code
    return code.replace("```python", "").replace("```", "").strip()

def run_k(task, k, max_workers=None):
    def _generate_one(i):
        code = coder(
            task=task,
            language="python",
            config={"rollout_id": i}
        ).code
        return code.replace("```python", "").replace("```", "").strip()

    with ThreadPoolExecutor(max_workers=max_workers or k) as executor:
        return list(executor.map(_generate_one, range(k)))


def run_example(path=None, str=None, min_scenarios=3):

    scenarios = regenerate(path, str, n=min_scenarios)
    results = []

    for scenario in scenarios:
        code = coder(task=scenario, language="python").code
        results.append(code.replace("```python", "").replace("```", "").strip())

    return scenarios, results

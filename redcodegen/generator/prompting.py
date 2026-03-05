from concurrent.futures import ThreadPoolExecutor

import dspy
from redcodegen.scenarios import regenerate


class GenerateCode(dspy.Signature):
    """Given the prompt, generate code that solves the task; as a reminder, you should be writing production code (i.e. disable any debugging traces, etc.) Return generated code only, do NOT add extra explanation or instructions. If test code is provided, ensure the solution passes those tests."""

    task: str = dspy.InputField()
    language: str = dspy.InputField()
    test_code: str = dspy.InputField(default="", desc="Pytest test code the solution must pass (may be empty)")
    code: str = dspy.OutputField(desc="Generated source code to solve the task; do not add extra explanation, instructions, or text.")

coder = dspy.ChainOfThought(GenerateCode)

def run(task, test_code=""):
    code = coder(task=task, language="python", test_code=test_code).code
    return code.replace("```python", "").replace("```", "").strip()

def run_k(task, k, max_workers=None, test_code=""):
    def _generate_one(i):
        code = coder(
            task=task,
            language="python",
            test_code=test_code,
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

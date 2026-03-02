"""
contrastive.py

generate contrastive learning data!
given amplify outputs, we want to collect the failure examples
and roll them out to get paired preferences. for each prompt, we
make k *pairs* of continuations. one fails static validation and
one works. and thus we are able to get data for e.g., DPO.
"""

from redcodegen.generator.prompting import coder
from redcodegen.validator import evaluate

from loguru import logger

def rollout_k_pairs(prompt, k=5, max_rollouts=20):
    """Given a string prompt, roll out some generations to make paired answers

    Args:
        prompt (str): the prompt to generate code for
        k (int): the number of pairs to generate
        max_rollouts (int): the maximum number of rollouts to attempt before giving up

    Returns:
        list[tuple[str, str]]
        a list of (success, failure) pairs of generated code, where success is a code
        snippet that passes validation and failure is a code snippet that fails validation
    """

    failure_info = []
    failures = []
    successes = []
    
    rollouts = 0
    while (len(list(zip(failures, successes))) < k) and (rollouts < max_rollouts):
        logger.debug(f"Rollout {rollouts}/{max_rollouts} for prompt: {prompt[:10]}...")
        code = coder(
            task=prompt,
            language="python",
            config={"rollout_id": rollouts, "temperature": 1.0}
        ).code
        code = code.replace("```python", "").replace("```", "").strip()
        res = evaluate(code)
        if len(res) > 0:
            logger.debug(f"Vulnerability found in rollout {rollouts}!")
            failures.append(code)
            failure_info.append(res[0])
        else:
            logger.debug(f"Vulnerability not found in rollout {rollouts}!")
            successes.append(code)
        rollouts += 1

    return list(zip(successes, failures, failure_info))



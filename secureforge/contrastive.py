"""
contrastive.py

generate contrastive learning data!
given amplify outputs, we want to collect the failure examples
and roll them out to get paired preferences. for each prompt, we
make k *pairs* of continuations. one fails static validation and
one works. and thus we are able to get data for e.g., DPO.
"""

from secureforge.generator.prompting import coder
from secureforge.validator import evaluate
from secureforge.language import get_language_config, DEFAULT_LANGUAGE

from loguru import logger

def rollout_k_pairs(prompt, k=5, max_rollouts=20, language=DEFAULT_LANGUAGE):
    """Given a string prompt, roll out some generations to make paired answers

    Args:
        prompt (str): the prompt to generate code for
        k (int): the number of pairs to generate
        max_rollouts (int): the maximum number of rollouts to attempt before giving up
        language (str): target programming language

    Returns:
        list[tuple[str, str, Any]]
        a list of (success, failure, failure_info) tuples of generated code
    """
    lang_config = get_language_config(language)

    failure_info = []
    failures = []
    successes = []

    rollouts = 0
    while (len(list(zip(failures, successes))) < k) and (rollouts < max_rollouts):
        logger.debug(f"Rollout {rollouts}/{max_rollouts} for prompt: {prompt[:10]}...")
        code = coder(
            task=prompt,
            language=lang_config.name,
            config={"rollout_id": rollouts, "temperature": 1.0}
        ).code
        code = code.replace(f"```{lang_config.code_fence}", "").replace("```", "").strip()
        res = evaluate(code, language=language)
        if len(res) > 0:
            logger.debug(f"Vulnerability found in rollout {rollouts}!")
            failures.append(code)
            failure_info.append(res[0])
        else:
            logger.debug(f"Vulnerability not found in rollout {rollouts}!")
            successes.append(code)
        rollouts += 1

    return list(zip(successes, failures, failure_info))



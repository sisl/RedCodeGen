import math
import random
import logging
from typing import Tuple
from dataclasses import dataclass

from redcodegen.generator import run_k
from redcodegen.validator import evaluate
from redcodegen.kernels import Kernel

logger = logging.getLogger("redcodegen")

@dataclass
class FailureBeta:
    failure_pseudocounts: int
    nominal_pseudocounts: int

def quantify(prompt, threshold=0.015, min_rollouts=5, no_fail_prior=1, fail_prior=1) -> FailureBeta:
    """Given prompt, we perform k rollouts or until variance threshold dips below threshold to obtain a beta distribution over failures."""

    k = min_rollouts
    var = float("+inf") 

    while var > threshold:
        results = run_k(prompt, k) # the first few will be cached, making this work
        evaluations = [evaluate(i) for i in results] # the first few will be cached

        fail = fail_prior
        no_fail = no_fail_prior

        for i in evaluations:
            if len(i) > 0:
                fail += 1
            else:
                no_fail += 1

        var = (fail*no_fail)/((fail+no_fail)**2 * (fail+no_fail+1))
        k += 1
        # print(var)

    return FailureBeta(
        failure_pseudocounts=fail, 
        nominal_pseudocounts=no_fail
    )


def mcmc(tau: str, kernel: Kernel, turns=100, find_failure=True, symmetric=False, threshold=0.015) -> list[Tuple[str, FailureBeta]]:
    """Run MCMC step; provide tau and a kernel, and we'll give tau'.

    We will keep sampling prompts until one acceptance happens,
    and return, the newly accepted sample.

    Args:
        tau (str): The initial prompt/trajectory.
        kernel (Kernel): The MCMC kernel to use for sampling.
        find_failure (bool): Find failures or find successes?
        turns (int): Number of MCMC turns to run, accept or not.
        symmetric (bool): Whether or not we consider proposal kernel as symmetric.
        threshold (optional, float): The variance of the beta distribution given must be below thi to stop sampling.

    Returns:
        str: The newly accepted prompt/trajectory.
    """

    # helper to score beta expected value
    if find_failure:
        fail_estimate_fn = lambda fd: ((fd.failure_pseudocounts -1)/
                                    (fd.failure_pseudocounts + fd.nominal_pseudocounts -2))
    else:
        fail_estimate_fn = lambda fd: ((fd.nominal_pseudocounts -1)/
                                    (fd.failure_pseudocounts + fd.nominal_pseudocounts -2))

    # compute distirbution of initial sample
    fail_dist = quantify(tau, threshold)
    samples = [(tau, fail_dist)]

    for i in range(turns):
        logger.debug("MCMC turn %d/%d", i+1, turns)

        # get next sample
        (tau, fail_dist) = samples[-1]
        tau_prime = kernel.sample(tau, state=(i+1)*(1 if find_failure else -1))
        fail_dist_prime = quantify(tau_prime, threshold)

        bonus = 0.0
        if not symmetric:
            bonus += kernel.condition(tau_prime, tau)-kernel.condition(tau, tau_prime)

        try:
            if (fail_estimate_fn(fail_dist_prime) > 0 and fail_estimate_fn(fail_dist) == 0):
                logger.debug("FORCE ACCEPT %s", str(fail_dist_prime)) # since this is negative infinity
                samples.append((tau_prime, fail_dist_prime))
            elif (fail_estimate_fn(fail_dist_prime) > 0 and # otherwise taking the log becomes -infty
                random.random() < math.exp((math.log(fail_estimate_fn(fail_dist_prime))-
                                            math.log(fail_estimate_fn(fail_dist))+
                                            bonus))):
                logger.debug("ACCEPT %s", str(fail_dist_prime))
                samples.append((tau_prime, fail_dist_prime))
            else:
                logger.debug("REJECT %s", str(fail_dist_prime))
        except:
            import ipdb
            ipdb.set_trace()

    return samples


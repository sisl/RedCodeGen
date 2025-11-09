import math
import random
import logging
from typing import Tuple
from dataclasses import dataclass

from redcodegen.generator import run_k
from redcodegen.validator import evaluate
from redcodegen.kernels import Kernel

logger = logging.getLogger(__name__)

@dataclass
class FailureBeta:
    failure_pseudocounts: int
    nominal_pseudocounts: int

def quantify(prompt, k=10, no_fail_prior=1, fail_prior=1) -> FailureBeta:
    """Given prompt, we perform k rollouts to obtain a beta distribution over failures."""

    results = run_k(prompt, k)
    evaluations = [evaluate(i) for i in results]

    fail = fail_prior
    no_fail = no_fail_prior

    for i in evaluations:
        if len(i) > 0:
            fail += 1
        else:
            no_fail += 1

    return FailureBeta(
        failure_pseudocounts=fail, 
        nominal_pseudocounts=no_fail
    )


def mcmc(tau: str, kernel: Kernel, turns=100, k=10) -> list[Tuple[str, FailureBeta]]:
    """Run MCMC step; provide tau and a kernel, and we'll give tau'.

    We will keep sampling prompts until one acceptance happens,
    and return, the newly accepted sample.

    Args:
        tau (str): The initial prompt/trajectory.
        kernel (Kernel): The MCMC kernel to use for sampling.
        turns (int): Number of MCMC turns to run, accept or not.
        K (optional, int): Number of trials we use to estimate failure probability.

    Returns:
        str: The newly accepted prompt/trajectory.
    """

    # helper to score beta expected value
    fail_estimate_fn = lambda fd: ((fd.failure_pseudocounts)/
                                   (fd.failure_pseudocounts + fd.nominal_pseudocounts))

    # compute distirbution of initial sample
    fail_dist = quantify(tau, k)
    samples = [(tau, fail_dist)]

    for i in range(turns):
        logger.debug("MCMC turn %d/%d", i+1, turns)

        # get next sample
        (tau, fail_dist) = samples[-1]
        tau_prime = kernel.sample(tau)
        fail_dist_prime = quantify(tau_prime, k)

        if random.random() < math.exp((math.log(fail_estimate_fn(fail_dist_prime))-math.log(fail_estimate_fn(fail_dist))+
                                       kernel.condition(tau_prime, tau)-kernel.condition(tau, tau_prime))):
            samples.append((tau_prime, fail_dist_prime))

    return samples


import math
import random
from typing import Tuple
from dataclasses import dataclass
from loguru import logger
# from multiprocessing import Pool

from secureforge.generator.prompting import run_k
from secureforge.analyzers.evaluate import evaluate
from secureforge.analyzers.common import AnalysisTool
from secureforge.kernels import Kernel
from secureforge.language import DEFAULT_LANGUAGE

@dataclass
class FailureBeta:
    failure_pseudocounts: int
    nominal_pseudocounts: int

def quantify(
        prompt, threshold=0.015, min_rollouts=5, no_fail_prior=1,
        fail_prior=1, language=DEFAULT_LANGUAGE,
        analysis_tool: AnalysisTool = AnalysisTool.SEMGREP,
) -> Tuple[FailureBeta, list[dict]]:
    """Given prompt, perform k rollouts until variance threshold is met.

    Returns:
        Tuple of (FailureBeta, rollouts) where each rollout is
        {"code": str, "vulnerabilities": list[dict]}.
    """

    k = min_rollouts
    var = float("+inf")

    evaluations_cache = {}
    logger.debug("quantify: starting with threshold={}, min_rollouts={}, prompt={!r}",
                 threshold, min_rollouts, prompt[:80])

    iteration = 0
    while var > threshold:
        iteration += 1
        results = run_k(prompt, k, language=language) # the first few will be cached, making this work
        logger.debug("quantify: iteration {} — requested k={}, got {} results ({} cached)",
                     iteration, k, len(results), sum(1 for r in results if r in evaluations_cache))

        # see which evaluations have been completed, and which ones have not
        evaluations = []
        remaining = []
        for i in results:
            existing_eval = evaluations_cache.get(i)
            if existing_eval is not None:
                evaluations.append(existing_eval)
            else:
                remaining.append(i)

        # launch evaluation jobs for remaining items in parallel
        for code in remaining:
            evaluation = evaluate(code, analysis_tool=analysis_tool, language=language)
            evaluations_cache[code] = evaluation
            evaluations.append(evaluation)
            if evaluation:
                rules = [v.get("rule", "?") for v in evaluation]
                logger.debug("quantify: rollout has {} vulnerabilities: {}", len(evaluation), rules)

        fail = fail_prior
        no_fail = no_fail_prior

        for i in evaluations:
            if len(i) > 0:
                fail += 1
            else:
                no_fail += 1

        var = (fail*no_fail)/((fail+no_fail)**2 * (fail+no_fail+1))
        logger.debug("quantify: iteration {} — fail={}, no_fail={}, var={:.6f} (threshold={})",
                     iteration, fail - fail_prior, no_fail - no_fail_prior, var, threshold)
        k += 1

    beta = FailureBeta(failure_pseudocounts=fail, nominal_pseudocounts=no_fail)
    rollouts = [{"code": code, "vulnerabilities": vulns}
                for code, vulns in evaluations_cache.items()]
    logger.debug("quantify: converged after {} iterations — beta={}, {} rollouts",
                 iteration, beta, len(rollouts))
    return beta, rollouts


def rephrase_baseline(
    tau: str,
    kernel: Kernel,
    k: int = 100,
    threshold: float = 0.015,
    language: str = DEFAULT_LANGUAGE,
    analysis_tool: AnalysisTool = AnalysisTool.SEMGREP,
) -> list[Tuple[str, FailureBeta, list[dict]]]:
    """Resample the *original* prompt k times via the kernel — non-MCMC baseline.

    Unlike mcmc(), every proposal is drawn from the seed prompt tau (not the
    previously-accepted sample) and every proposal is kept (no Metropolis–Hastings
    accept/reject). Output shape mirrors mcmc(): a list of (prompt, FailureBeta,
    rollouts) tuples, with the seed sample at index 0 followed by k rephrased
    draws. Whether a draw is "secure" vs "insecure" is recoverable from each
    rollout's vulnerabilities list.
    """

    logger.debug("rephrase_baseline: k={}, threshold={}, seed={!r}", k, threshold, tau[:100])

    seed_beta, seed_rollouts = quantify(tau, threshold, language=language, analysis_tool=analysis_tool)
    samples: list[Tuple[str, FailureBeta, list[dict]]] = [(tau, seed_beta, seed_rollouts)]

    for i in range(k):
        tau_prime = kernel.sample(tau, state=i + 1)
        logger.debug("rephrase_baseline: draw {}/{} — proposal={!r}", i + 1, k, tau_prime[:100])
        beta, rollouts = quantify(tau_prime, threshold, language=language, analysis_tool=analysis_tool)
        samples.append((tau_prime, beta, rollouts))
        logger.debug("rephrase_baseline: draw {}/{} — beta={}, {} rollouts", i + 1, k, beta, len(rollouts))

    logger.debug("rephrase_baseline: finished — {} samples (1 seed + {} draws)", len(samples), k)
    return samples


def mcmc(tau: str, kernel: Kernel, turns=100, find_failure=True, symmetric=False, threshold=0.015, language=DEFAULT_LANGUAGE, analysis_tool: AnalysisTool = AnalysisTool.SEMGREP) -> list[Tuple[str, FailureBeta, list[dict]]]:
    """Run MCMC chain starting from tau.

    Args:
        tau: The initial prompt/trajectory.
        kernel: The MCMC kernel to use for sampling.
        find_failure: Find failures or find successes?
        turns: Number of MCMC turns to run, accept or not.
        symmetric: Whether or not we consider proposal kernel as symmetric.
        threshold: The variance of the beta distribution must be below this to stop sampling.

    Returns:
        List of (prompt, FailureBeta, rollouts) for accepted samples, where
        each rollout is {"code": str, "vulnerabilities": list[dict]}.
    """

    # helper to score beta expected value
    if find_failure:
        fail_estimate_fn = lambda fd: ((fd.failure_pseudocounts -1)/
                                    (fd.failure_pseudocounts + fd.nominal_pseudocounts -2))
    else:
        fail_estimate_fn = lambda fd: ((fd.nominal_pseudocounts -1)/
                                    (fd.failure_pseudocounts + fd.nominal_pseudocounts -2))

    # compute distribution of initial sample
    logger.debug("mcmc: mode={}, turns={}, threshold={}, symmetric={}",
                 "failure" if find_failure else "success", turns, threshold, symmetric)
    logger.debug("mcmc: seed prompt={!r}", tau[:100])
    fail_dist, rollouts = quantify(tau, threshold, language=language, analysis_tool=analysis_tool)
    logger.debug("mcmc: seed quantified — beta={}, score={:.4f}, {} rollouts",
                 fail_dist, fail_estimate_fn(fail_dist), len(rollouts))
    samples = [(tau, fail_dist, rollouts)]

    accepted = 0
    for i in range(turns):
        # get next sample
        (tau, fail_dist, _) = samples[-1]
        tau_prime = kernel.sample(tau, state=(i+1)*(1 if find_failure else -1))
        logger.debug("mcmc: turn {}/{} — proposal={!r}", i+1, turns, tau_prime[:100])
        fail_dist_prime, rollouts_prime = quantify(tau_prime, threshold, language=language, analysis_tool=analysis_tool)

        current_score = fail_estimate_fn(fail_dist)
        proposal_score = fail_estimate_fn(fail_dist_prime)

        bonus = 0.0
        if not symmetric:
            bonus += kernel.condition(tau_prime, tau)-kernel.condition(tau, tau_prime)

        try:
            if (proposal_score > 0 and current_score == 0):
                accepted += 1
                logger.debug("mcmc: turn {}/{} — FORCE ACCEPT (score {:.4f} > 0, current=0) beta={} [{} accepted]",
                             i+1, turns, proposal_score, fail_dist_prime, accepted)
                samples.append((tau_prime, fail_dist_prime, rollouts_prime))
            elif (proposal_score > 0 and
                random.random() < math.exp((math.log(proposal_score)-
                                            math.log(current_score)+
                                            bonus))):
                accepted += 1
                logger.debug("mcmc: turn {}/{} — ACCEPT (score {:.4f} vs {:.4f}) beta={} [{} accepted]",
                             i+1, turns, proposal_score, current_score, fail_dist_prime, accepted)
                samples.append((tau_prime, fail_dist_prime, rollouts_prime))
            else:
                logger.debug("mcmc: turn {}/{} — REJECT (score {:.4f} vs {:.4f}) beta={}",
                             i+1, turns, proposal_score, current_score, fail_dist_prime)
        except:
            import ipdb
            ipdb.set_trace()

    logger.debug("mcmc: finished — {}/{} accepted, {} total samples (including seed)",
                 accepted, turns, len(samples))
    return samples


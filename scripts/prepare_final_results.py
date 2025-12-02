# - keywords for proposal vs mcmc vs baseline 
# - self-BLEU string diversity for proposal vs mcmc vs baseline 
# - pass ratio@k over baseline for both mcmc, proposal
# - pass ratio@1 over baseline for both mcmc, proposal
# - failure rate historgram (which errors are most common) <- not sure what's the best plov

import csv
import json
import jsonlines
import pandas as pd
import seaborn as sns
import matplotlib
import matplotlib.pyplot as plt
from pathlib import Path

from matplotlib.backends.backend_pgf import FigureCanvasPgf
matplotlib.backend_bases.register_backend('pdf', FigureCanvasPgf)

FIGSIZE=(4,6)

sns.set_style("whitegrid")
sns.set_context("paper", font_scale=1.5)
sns.set_palette(["#8C1515",    # Stanford Red
                 "#175E54",    # Palo Alto Green
                 "#E98300",    # Stanford Orange
                 "#E6BBB3",    # Soft Pink
                 "#007C92",    # Teal
                 "#DAD7CB",    # Light Gray
                 "#B83A4B",    # Cardinal Red
                 "#4D4F53"])   # Dark Gray
matplotlib.rcParams.update({
    "pgf.texsystem": "pdflatex",
    'pgf.rcfonts': False,
    'font.family': 'serif',
    'font.serif': ['Computer Modern Roman'],
    'text.usetex': True
})

BASELINE = "./output/collected/cwe_top_25_gpt4omini.jsonl"
MCMC = "./output/collected/cwe_top_25_gpt4omini_mcmc.jsonl"
PROPOSAL = "./output/collected/cwe_proposal_gpt4omini.jsonl"

with jsonlines.open(BASELINE, 'r') as data:
    baseline = sum([i["samples"] for i in data], [])
    baseline_successes = [
        i for i in baseline if len(i["evaluation"]) == 0
    ]
    baseline_failures = [
        i for i in baseline if len(i["evaluation"]) > 0
    ]
with jsonlines.open(MCMC, 'r') as data:
    mcmc = [i for i in data]
    mcmc_successes = sum([i["mcmc_successes"] for i in mcmc], [])
    mcmc_failures = sum([i["mcmc_failures"] for i in mcmc], [])
with jsonlines.open(PROPOSAL, 'r') as data:
    proposal = [i for i in data]
    proposal_nominal = [i for i in proposal if i["goal"] == "nominal"]
    proposal_failure = [i for i in proposal if i["goal"] == "failure"]

#################################################################

# pass amplification measurements

baseline_rate = len(baseline_failures) / len(baseline)
mcmc_failure_pass_at_1 = (
    sum([i["num_failures"] for i in mcmc_failures])/
    sum([i["num_failures"]+i["num_successes"] for i in mcmc_failures])
)
mcmc_failure_pass_at_n = (
    sum([i["num_failures"] > 0 for i in mcmc_failures])/len(mcmc_failures)
)
proposal_failure_pass_at_1 = (
    sum([i["result"]["failure"] for i in proposal_failure]) /
    sum([i["result"]["failure"] +
         i["result"]["nominal"] for i in proposal_failure])
)
proposal_failure_pass_at_n = (
    sum([i["result"]["failure"]>0 for i in proposal_failure]) /
    len(proposal_failure)
)
mcmc_ratio_at_1 = mcmc_failure_pass_at_1 / baseline_rate
mcmc_ratio_at_n = mcmc_failure_pass_at_n / baseline_rate
proposal_ratio_at_1 = proposal_failure_pass_at_1 / baseline_rate
proposal_ratio_at_n = proposal_failure_pass_at_n / baseline_rate

#################################################################

# self-BLEU measurements
def compute_self_bleu(samples):
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    from nltk import word_tokenize
    smoothie = SmoothingFunction().method4

    bleu_scores = []
    for i, sample in enumerate(samples):
        references = [word_tokenize(s) for j, s in enumerate(samples) if j != i]
        candidate = word_tokenize(sample)
        bleu_score = sentence_bleu(references, candidate, weights=(0.2, 0.2, 0.2, 0.2, 0.2), smoothing_function=smoothie)
        bleu_scores.append(bleu_score)
    return sum(bleu_scores) / len(bleu_scores)

baseline_self_bleu = compute_self_bleu([i["scenario"] for i in baseline_failures])
mcmc_self_bleu = compute_self_bleu([i["prompt"] for i in mcmc_failures])
proposal_self_bleu = compute_self_bleu([i["prompt"] for i in proposal_failure])

proposal_self_bleu
baseline_self_bleu
mcmc_self_bleu

#################################################################

# error type distributions
baseline_error_types = [j["rule"] for i in baseline_failures for j in i["evaluation"]]
proposal_error_types = sum([i["result"]["error_types"] for i in proposal_failure],[])

from collections import Counter
baseline_error_counts = Counter(baseline_error_types)
proposal_error_counts = Counter(proposal_error_types)

proposal_error_counts

baseline_error_counts




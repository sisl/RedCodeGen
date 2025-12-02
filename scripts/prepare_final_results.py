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

#################################################################

# error type distributions
baseline_error_types = [j["rule"] for i in baseline_failures for j in i["evaluation"]]
proposal_error_types = sum([i["result"]["error_types"] for i in proposal_failure],[])

from collections import Counter
baseline_error_counts = Counter(baseline_error_types)
proposal_error_counts = Counter(proposal_error_types)

#################################################################

## <these two bar charts, side by side>
# Create figure with three subplots
fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(12, 4))

# Data for the charts
methods = ['Baseline', 'MCMC', 'Learned\nProposal']
pass_at_1_values = [baseline_rate, mcmc_failure_pass_at_1, proposal_failure_pass_at_1]
pass_at_n_values = [baseline_rate, mcmc_failure_pass_at_n, proposal_failure_pass_at_n]
self_bleu_values = [baseline_self_bleu, mcmc_self_bleu, proposal_self_bleu]

# First bar chart: Pass@1
bars1 = sns.barplot(x=methods, y=pass_at_1_values, ax=ax1, hue=methods, width=0.6, legend=False)
ax1.set_ylabel('Failure Rate')
ax1.set_xlabel('')
ax1.set_title('Pass@1 $(\\uparrow)$')
ax1.set_ylim(0, max(pass_at_1_values) * 1.2)
ax1.grid(True, linestyle='--', alpha=0.7)
ax1.tick_params(axis='both', which='major', labelsize=10)
# Annotate values
for i, (bar, val) in enumerate(zip(ax1.patches, pass_at_1_values)):
    ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(pass_at_1_values) * 0.02,
             f'{val:.3f}', ha='center', va='bottom', fontsize=9)

# Second bar chart: Pass@n
bars2 = sns.barplot(x=methods, y=pass_at_n_values, ax=ax2, hue=methods, width=0.6, legend=False)
ax2.set_ylabel('Failure Rate')
ax2.set_xlabel('')
ax2.set_title('Pass@n $(\\uparrow)$')
ax2.set_ylim(0, max(pass_at_n_values) * 1.2)
ax2.grid(True, linestyle='--', alpha=0.7)
ax2.tick_params(axis='both', which='major', labelsize=10)
# Annotate values
for i, (bar, val) in enumerate(zip(ax2.patches, pass_at_n_values)):
    ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(pass_at_n_values) * 0.02,
             f'{val:.3f}', ha='center', va='bottom', fontsize=9)

# Third bar chart: Self-BLEU
bars3 = sns.barplot(x=methods, y=self_bleu_values, ax=ax3, hue=methods, width=0.6, legend=False)
ax3.set_ylabel('Self-BLEU')
ax3.set_xlabel('')
ax3.set_title('Self-BLEU (Diversity) $(\\downarrow)$')
ax3.set_ylim(0, max(self_bleu_values) * 1.2)
ax3.grid(True, linestyle='--', alpha=0.7)
ax3.tick_params(axis='both', which='major', labelsize=10)
# Annotate values
for i, (bar, val) in enumerate(zip(ax3.patches, self_bleu_values)):
    ax3.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(self_bleu_values) * 0.02,
             f'{val:.3f}', ha='center', va='bottom', fontsize=9)

plt.tight_layout()
plt.savefig('./figures/failure_rate_comparison.pdf', bbox_inches='tight')
## </these two bar charts, side by side>

## Plot error type distributions as pie charts
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8, 3))

# Get all unique error types and assign consistent colors
all_error_types = set(baseline_error_counts.keys()) | set(proposal_error_counts.keys())
color_palette = sns.color_palette("tab20", len(all_error_types))
color_map = {error_type: color_palette[i] for i, error_type in enumerate(sorted(all_error_types))}

# Helper function to create labels (only show categories above threshold)
def create_labels(counts, threshold_pct=10.0):
    total = sum(counts.values())
    sorted_items = counts.most_common()
    labels = []
    for error_type, count in sorted_items:
        pct = (count / total) * 100
        if pct >= threshold_pct:
            labels.append(error_type)
        else:
            labels.append('')  # Empty label for smaller slices
    return labels

# Function to only show percentages for slices above threshold
def autopct_format(pct, threshold=10.0):
    return f'{pct:.1f}\\%' if pct >= threshold else ''

# Baseline error counts pie chart
baseline_items = baseline_error_counts.most_common()
baseline_labels = create_labels(baseline_error_counts, threshold_pct=5.0)
baseline_values = [count for _, count in baseline_items]
baseline_colors = [color_map[error_type] for error_type, _ in baseline_items]

wedges1, texts1, autotexts1 = ax1.pie(baseline_values, labels=baseline_labels,
                                        autopct=lambda pct: autopct_format(pct, threshold=5.0),
                                        startangle=90, colors=baseline_colors,
                                        textprops={'fontsize': 9})
ax1.set_title('Baseline Error Types')

# Proposal error counts pie chart
proposal_items = proposal_error_counts.most_common()
proposal_labels = create_labels(proposal_error_counts, threshold_pct=5.0)
proposal_values = [count for _, count in proposal_items]
proposal_colors = [color_map[error_type] for error_type, _ in proposal_items]

wedges2, texts2, autotexts2 = ax2.pie(proposal_values, labels=proposal_labels,
                                        autopct=lambda pct: autopct_format(pct, threshold=5.0),
                                        startangle=90, colors=proposal_colors,
                                        textprops={'fontsize': 9})
ax2.set_title('Learned Proposal Error Types')

plt.tight_layout()
plt.savefig('./figures/error_type_distributions.pdf', bbox_inches='tight')
plt.show()

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

DATA = "./output/cwe_top_25_gpt4omini_mcmc.jsonl"
OUTPUT = "./output/cwe_extended_train_gpt4omini.json"
THRESHOLD = 0.6 # a failure is a failure if its > 50%, etc.

with jsonlines.open(DATA, 'r') as rd:
    data = [i for i in rd]


results = {}
success_count = 0
failure_count = 0
for i in data:
    successes = []
    failures = []
    for success in i["mcmc_successes"]:
        if success["num_successes"]/sum(
            [success["num_successes"], success["num_failures"]]
        ) > THRESHOLD:
            successes.append(success["prompt"])
    for failure in i["mcmc_failures"]:
        if failure["num_failures"]/sum(
            [failure["num_successes"], failure["num_failures"]]
        ) > THRESHOLD:
            failures.append(failure["prompt"])

    if not results.get(i["type"]):
        results[i["type"]] = {
            "successes": [],
            "failures": []
        }

    results[i["type"]]["successes"] +=  successes
    results[i["type"]]["failures"] +=  failures
    success_count += len(successes)
    failure_count += len(failures)

print(success_count, failure_count)

with open(OUTPUT, 'w') as wd:
    json.dump(results, wd, indent=4)

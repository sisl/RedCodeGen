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


DATA = "./data/cwe_proposal_gpt4omini_move.jsonl"

with jsonlines.open(DATA) as reader:
    data = [obj for obj in reader]

results = []
for i in data:
    results.append({
        "goal": i["goal"],
        "failure": i["result"]["failure"],
        "nominal": i["result"]["nominal"]
    })

df = pd.DataFrame(results)
df["failure_rate"] = df.failure /(df.failure+df.nominal)

asr_overall = df[df.goal == "failure"].failure_rate.mean() # 44.9%
asr_pass_at_n = (df[df.goal == "failure"].failure > 0).sum() / len(df[df.goal == "failure"].failure) # 84.6%

asr_overall_nom = df[df.goal == "nominal"].failure_rate.mean() # 45.1% mmm
asr_pass_at_n_nom = (df[df.goal == "nominal"].failure > 0).sum() / len(df[df.goal == "nominal"].failure) # 64.3%


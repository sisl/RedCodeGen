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

DATA = "./data/cwe_top_25_gpt5mini.jsonl"
OUT = Path("./figures/")

with jsonlines.open(DATA, 'r') as d:
    data = [i for i in d]
all_samples = []

for i in data:
    for sample in i["samples"]:
        s = sample
        s["cwe"] = i["cwe_id"]
        s["vulnerabilities"] = s["evaluation"]
        all_samples.append(s)
        if len(s["evaluation"]) > 0:
            risks = list(i["rule"] for i in s["evaluation"])
            majority_risk = max(set(risks), key = risks.count)
            s["vulnerability"] = majority_risk
        del s["evaluation"]

df = pd.DataFrame(all_samples)
counts = df.vulnerability.value_counts().reset_index()
# vulnerability
# py/url-redirection                      16
# py/path-injection                       11
# py/stack-trace-exposure                  8
# py/full-ssrf                             7
# py/command-line-injection                4
# py/reflective-xss                        2
# py/clear-text-logging-sensitive-data     2
# py/code-injection                        1
# Name: count, dtype: int64
g = sns.barplot(data=counts, x="vulnerability", y="count")
g.set_xticklabels(g.get_xticklabels(), rotation=90)
g.set(xlabel="")
plt.savefig("figures/gpt5_vuln.pdf", bbox_inches='tight', pad_inches=0.3)
df.to_csv("./figures/gpt5.csv", index=False)



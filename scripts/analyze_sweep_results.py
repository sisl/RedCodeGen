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
    'pgf.rcfonts': True,
    'font.family': 'serif',
    'font.serif': ['DejaVu Sans Mono'],
    'text.usetex': False
})

DATA = "./output/e0_gpt4o/metrics_summary.csv"
df = pd.read_csv(DATA)

# get only thohse for which sample size is decent
# df = df[df.n >= 125]

df.asr_pass_at_n = pd.to_numeric(df.asr_pass_at_n)
df.asr_pass_at_n_nom = pd.to_numeric(df.asr_pass_at_n_nom)
df.asr_overall = pd.to_numeric(df.asr_overall)
df.asr_overall_nom = pd.to_numeric(df.asr_overall_nom)

df["pass_at_n_diff"] = (df.asr_pass_at_n - df.asr_pass_at_n_nom)
df["overall_diff"] = (df.asr_overall - df.asr_overall_nom)
df["sum_diff"] = df.pass_at_n_diff + df.overall_diff
df["dpo"] = df.filename.str.contains("dpo")

sns.scatterplot(data=df, x="asr_pass_at_n", y="asr_pass_at_n_nom", size="n", hue="dpo")
sns.scatterplot(data=df, x="asr_overall", y="asr_overall_nom", size="n", hue="dpo")

df.sort_values(by="sum_diff", ascending=False).iloc[:5]

df.asr_pass_at_n

df[((df.asr_pass_at_n > 0.4)&(df.asr_pass_at_n < 0.4)&
    (df.asr_pass_at_n_nom < 0.4))&(df.n > 100)]


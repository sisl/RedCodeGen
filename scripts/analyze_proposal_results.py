import csv
import json
import jsonlines
import pandas as pd
import seaborn as sns
import matplotlib
import matplotlib.pyplot as plt
from pathlib import Path
import re

from matplotlib.backends.backend_pgf import FigureCanvasPgf
matplotlib.backend_bases.register_backend('pdf', FigureCanvasPgf)

FIGSIZE=(6,4)

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

# matplotlib.rcParams.update({
#     "pgf.texsystem": "pdflatex",
#     'pgf.rcfonts': False,
#     'font.family': 'serif',
#     'font.serif': ['Computer Modern Roman'],
#     'text.usetex': True
# })


# DATA = "./output/e0_gpt4o/e0_gpt4o_d2048_s1e1024_s2e128_lr46_dpo.jsonl"
OUTPUT_DIR = Path("./output/e0_gpt4o/")
all_results = []

for data_file in OUTPUT_DIR.glob("*.jsonl"):
    try:
        with jsonlines.open(data_file) as reader:
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

        asr_overall = df[df.goal == "failure"].failure_rate.mean()
        asr_pass_at_n = (df[df.goal == "failure"].failure > 0).sum() / len(df[df.goal == "failure"].failure)

        asr_overall_nom = df[df.goal == "nominal"].failure_rate.mean()
        asr_pass_at_n_nom = (df[df.goal == "nominal"].failure > 0).sum() / len(df[df.goal == "nominal"].failure)

        # Parse filename: e0_gpt4o_d${dataset_size}_s1e${epoch_1}_s2e${epoch_2}_lr46_dpo.jsonl
        match = re.search(r'd(\d+)_s1e(\d+)_s2e(\d+)', data_file.name)
        if match:
            dataset_size, epoch_1, epoch_2 = match.groups()
        else:
            dataset_size, epoch_1, epoch_2 = None, None, None

        all_results.append({
            "filename": data_file.name,
            "dataset_size": int(dataset_size) if dataset_size else None,
            "epoch_1": int(epoch_1) if epoch_1 else None,
            "epoch_2": int(epoch_2) if epoch_2 else None,
            "asr_overall": asr_overall,
            "asr_pass_at_n": asr_pass_at_n,
            "asr_overall_nom": asr_overall_nom,
            "asr_pass_at_n_nom": asr_pass_at_n_nom
        })
    except Exception as e:
        print(f"Error processing {data_file}: {e}")

results_df = pd.DataFrame(all_results)
results_df.to_csv("./output/e0_gpt4o/metrics_summary.csv", index=False)
print(f"Saved metrics for {len(all_results)} files to ./output/e0_gpt4o/metrics_summary.csv")

# Plot metrics
if len(results_df) > 0:
    fig, ax = plt.subplots(figsize=FIGSIZE)

    results_df_sorted = results_df.sort_values('dataset_size')

    ax.plot(results_df_sorted['dataset_size'], results_df_sorted['asr_overall'], marker='o', label='ASR Overall (Failure)')
    ax.plot(results_df_sorted['dataset_size'], results_df_sorted['asr_pass_at_n'], marker='s', label='ASR Pass@N (Failure)')
    ax.plot(results_df_sorted['dataset_size'], results_df_sorted['asr_overall_nom'], marker='^', label='ASR Overall (Nominal)')
    ax.plot(results_df_sorted['dataset_size'], results_df_sorted['asr_pass_at_n_nom'], marker='d', label='ASR Pass@N (Nominal)')

    ax.set_xlabel('Dataset Size')
    ax.set_ylabel('Attack Success Rate')
    ax.set_title('ASR Metrics vs Dataset Size')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('./output/e0_gpt4o/metrics_plot.pdf')
    print("Saved plot to ./output/e0_gpt4o/metrics_plot.pdf")

import os
import jsonlines
from openai import OpenAI
import pandas as pd
from collections import defaultdict

from dotenv import load_dotenv
load_dotenv()

import logging
logger = logging.getLogger("redcodegen")

from redcodegen.kernels import LMRephrasingKernel
from redcodegen.uncertainty import mcmc, FailureBeta

# user parametres
INPUT_FILE = "./output/cwe_top_25_gpt4omini.jsonl"
MCMC_STEPS = 16
VARIANCE_THRESHOLD=0.015

# load the failures
with jsonlines.open("./output/cwe_top_25_gpt4omini.jsonl", 'r') as d:
    data = [i for i in d]

all_samples = sum([i["samples"] for i in data], [])
vulnerable_samples = [i for i in all_samples if len(i["evaluation"]) > 0]

# collect failures based on failure type
failures = defaultdict(list)
for i in vulnerable_samples:
    failures[i["evaluation"][0]["rule"]].append(i)
failures = dict(failures)

# total output to write to file TODO
OUTPUT_DATA = []

# for each failure, perform MCMC sampling 
for failure, sample in failures.items():
    # TODO logging as needed for progress, feel free to
    # add things to loop such as enumerate

    for scenario in sample:
        
        # perform MCMC sampling to find nearby failures and successes
        successes = mcmc(
            scenario["scenario"],
            LMRephrasingKernel(),
            turns=MCMC_STEPS,
            find_failure=False,
            threshold=VARIANCE_THRESHOLD,
            symmetric=True
        )
        failures = mcmc(
            scenario["scenario"],
            LMRephrasingKernel(),
            turns=MCMC_STEPS,
            find_failure=True,
            threshold=VARIANCE_THRESHOLD,
            symmetric=True
        )

        successes_out = [
            {
                "prompt": i,
                "num_successes": j.nominal_pseudocounts-1,
                "num_failures": j.failure_pseudocounts-1
            }
            for i,j in successes
        ]
        failures_out = [
            {
                "prompt": i,
                "num_successes": j.nominal_pseudocounts-1,
                "num_failures": j.failure_pseudocounts-1
            }
            for i,j in failures
        ]

        OUTPUT_DATA.append({
            "type": failure,
            "seed": scenario["scenario"],
            "mcmc_successes": successes_out,
            "mcmc_failures": failures_out,
            "metadata": {
                "turns": MCMC_STEPS,
                "beta_variance_threshold": VARIANCE_THRESHOLD
            }
        })

# stick the output to the user given output file


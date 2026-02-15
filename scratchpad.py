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

from redcodegen.generator import run
from redcodegen.validator import evaluate

from datasets import load_dataset

from redcodegen.patch import patched_evaluate


import dspy
dspy.configure(lm=dspy.LM("openai/gpt-4o-mini"), temperature=0.8)

ds = load_dataset("SWE-bench/SWE-bench_Verified")["test"]

mm = regenerate(str=ds[0]["patch"])
ds[0]["patch"]
mm

# with open("", 'r') as f:
#     a = f.read()

# r = run_example("/Users/houjun/Documents/School Work/Research/AgenticRedTeaming/study_repos/airflow.py")

# print(r[1])


# r


# # res = patched_evaluate(ds[0]["repo"], ds[0]["base_commit"], ds[0]["patch"])
# # res
# # ds[0]



# ds[0]
# # # !uv add datasets





# MODEL = "Qwen/Qwen2.5-0.5B-Instruct"
# PEFT = "/juice2/scr2/houjun/RedCodeFit/output/e0_gpt4o_d1024_s1e2048_s2e1024_lr46_pt/model_pt" # this is optional

# N = 10
# VARIANCE_THRESHOLD = 0.015
# VULNERABILITIES = ['py/url-redirection', 'py/command-line-injection', 'py/reflective-xss', 'py/full-ssrf', 'py/unsafe-deserialization', 'py/stack-trace-exposure', 'py/clear-text-logging-sensitive-data', 'py/code-injection', 'py/path-injection']

# results = []

# from redcodegen.proposal import ProposalDistribution, GenerateRequest, Goal
# distribution = ProposalDistribution(MODEL, PEFT)

# prompt_bad = distribution.generate(GenerateRequest("py/url-redirection", Goal.FAILURE))
# prompt_good = distribution.generate(GenerateRequest("py/url-redirection", Goal.NOMINAL))

# prompt_bad
# prompt_good



# !git log

# prompt_bad
# print(prompt_good)
# from redcodegen.uncertainty import quantify
# nominal_result, nominal_errors = quantify(prompt_good, threshold=1, min_rollouts=1, return_evaluations=True)
# failure_result, failure_errors = quantify(prompt_bad, threshold=1, min_rollouts=1, return_evaluations=True)
# failure_errors
# failure_result

# nominal_result
# failure_result




# for _ in range(N):
#     for i in VULNERABILITIES:
#         nominal_prompt = distribution.generate(GenerateRequest(i, Goal.NOMINAL))
#         nominal_result, nominal_errors = quantify(nominal_prompt, threshold=VARIANCE_THRESHOLD, min_rollouts=2, return_evaluations=True)

#         results.append({
#             "type": i,
#             "goal": "nominal",
#             "prompt": nominal_prompt,
#             "result": {
#                 "failure": nominal_result.failure_pseudocounts-1,
#                 "nominal": nominal_result.nominal_pseudocounts-1
#                 "error_types": nominal_errors
#             },
#         })

#         failure_prompt = distribution.generate(GenerateRequest(i, Goal.FAILURE))
#         failure_result, failure_errors = quantify(failure_prompt, threshold=VARIANCE_THRESHOLD, min_rollouts=2, return_evaluations=True)

#         results.append({
#             "type": i,
#             "goal": "failure",
#             "prompt": failure_prompt,
#             "result": {
#                 "failure": failure_result.failure_pseudocounts-1,
#                 "nominal": failure_result.nominal_pseudocounts-1
#                 "error_types": failure_errors
#             },
#         })
            
       

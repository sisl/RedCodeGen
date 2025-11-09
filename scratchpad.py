import os
import jsonlines
from openai import OpenAI
import pandas as pd
from collections import defaultdict

from dotenv import load_dotenv
load_dotenv()

import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(message)s",
)

client = OpenAI()

from redcodegen.generator import coder

# load the failures
with jsonlines.open("./data/cwe_top_25_gpt4omini.jsonl", 'r') as d:
    data = [i for i in d]

df = pd.DataFrame(data)

# load the prompts that contains failure
all_samples = sum([i["samples"] for i in data], [])
vulnerable_samples = [i for i in all_samples if len(i["evaluation"]) > 0]

from redcodegen.kernels import LMRephrasingKernel

res = mcmc(vulnerable_samples[0]["scenario"], LMRephrasingKernel())



# fail_dist = quantify(vulnerable_samples[0]["scenario"], 3)
# we use mean for failure estimate i.e. since we want to use beta as a posterior estimate after update 
# fail_estimate = (fail_dist.failure_pseudocounts)/(fail_dist.failure_pseudocounts + fail_dist.nominal_pseudocounts) 




# # organize vulenarbility based on type
# organized_samples = defaultdict(list)
# for i in vulnerable_samples:
#     for j in i["evaluation"]:
#         organized_samples[j["rule"]].append(i)
# organized_samples = dict(organized_samples)
# organized_samples.keys()


# from redcodegen.validator import evaluate
# from tqdm import tqdm

# embeddings = [
#     client.embeddings.create(
#         model="text-embedding-3-small",
#         input=vulnerable_samples[0]["scenario"].replace("'uploads'", "'feels_good_it_must_be_mine'")
#     )
# ]

# evaluated = [evaluate(i) for i in tqdm(runs)]
# runs = run_k(organized_samples["py/reflective-xss"][0]["scenario"], 5)
# embeddings = [np.array(client.embeddings.create(
#     model="text-embedding-3-small",
#     input=i
# ).data[0].embedding) for i in runs]
# embeddings1 = np.array(embeddings)

# runs = run_k(organized_samples["py/reflective-xss"][1]["scenario"], 5)
# embeddings = [np.array(client.embeddings.create(
#     model="text-embedding-3-small",
#     input=i
# ).data[0].embedding) for i in runs]
# embeddings2 = np.array(embeddings)

# runs = run_k(organized_samples["py/full-ssrf"][0]["scenario"], 5)
# embeddings = [np.array(client.embeddings.create(
#     model="text-embedding-3-small",
#     input=i
# ).data[0].embedding) for i in runs]
# embeddings3 = np.array(embeddings)


# embeddings1
# embeddings2
# embeddings = np.concat([embeddings1, embeddings2, embeddings3])


# scenarios_1 = [i["scenario"] for i in organized_samples["py/full-ssrf"]]
# scenarios_2 = [i["scenario"] for i in organized_samples["py/reflective-xss"]]

# embeddings_1 = [client.embeddings.create(
#     model="text-embedding-3-small",
#     input=i
# ).data[0].embedding for i in scenarios_1]
# embeddings_2 = [client.embeddings.create(
#     model="text-embedding-3-small",
#     input=i
# ).data[0].embedding for i in scenarios_2]
# embeddings_1 = np.array(embeddings_1)
# embeddings_2 = np.array(embeddings_2)
# embeddings = np.concat([embeddings_1, embeddings_2])

# sns.heatmap((embeddings @ embeddings.T))

# embeddings.shape
# embedding1.shape

# evaluated
# print(runs[0])

# evaluated
# evaluate(vulnerable_samples[0]["code"])
# evaluated

# task = organized_samples["py/reflective-xss"][0]["scenario"]
# for i in range(10, 1000):
#     code = coder(
#         task=task,
#         language="python",
#         config={"rollout_id": i}
#     ).code
#     code = code.replace("```python", "").replace("```", "").strip()
#     if len(evaluate(code)) > 0:
#         break
#     print(i)



# print(organized_samples["py/reflective-xss"][0]["code"])
# print(runs[0])
# # ####




# # # load the prompts that contains failure
# # preds = coder(
# #     task=vulnerable_samples[0]["scenario"],
# #     language="python",
# #     config={"logprobs": True}
# # )

# # preds2 = coder(
# #     task=vulnerable_samples[0]["scenario"],
# #     language="python",
# #     code=
# #     config={"logprobs": True}
# # )

# # coder.to_text
# # coder.compile
# # coder.predict.compile


# # vulnerable_samples[0]["scenario"]
# # response1 = client.embeddings.create(
# #     model="text-embedding-3-small",
# #     input=vulnerable_samples[0]["scenario"]
# # )
# # response2_alt = client.embeddings.create(
# #     model="text-embedding-3-small",
# #     input=vulnerable_samples[0]["scenario"].replace("'uploads'", "'feels_good_it_must_be_mine'")
# # )
# # response2 = client.embeddings.create(
# #     model="text-embedding-3-small",
# #     input=vulnerable_samples[0]["scenario"].replace("'uploads'", "'documents'")
# # )
# # response3 = client.embeddings.create(
# #     model="text-embedding-3-small",
# #     input=vulnerable_samples[0]["scenario"].replace("can be", "cannot be")
# # )
# # response3 = client.embeddings.create(
# #     model="text-embedding-3-small",
# #     input=vulnerable_samples[0]["scenario"].replace("image files", "text files")
# # )

# # embedding1 = response1.data[0].embedding
# # embedding2 = response2.data[0].embedding
# # embedding2_alt = response2_alt.data[0].embedding
# # embedding3 = response3.data[0].embedding

# # import numpy as np
# # np.array(embedding1).T @ np.array(embedding2)
# # np.array(embedding1).T @ np.array(embedding2_alt)
# # np.array(embedding1).T @ np.array(embedding3)
# # np.array(embedding2).T @ np.array(embedding2_alt)
# # np.array(embedding2).T @ np.array(embedding3)
# # np.array(embedding2_alt).T @ np.array(embedding3)



# # preds

# # preds.logprobs

# print([i for i in dir(kernel.predict)
#  if not i.startswith("__")])


# adapter =  dspy.ChatAdapter()
# base_messages = adapter.format(signature=GenerateConditionedPrompt, demos=[], inputs={"task": "CHICKENS!!!"})
# base_messages


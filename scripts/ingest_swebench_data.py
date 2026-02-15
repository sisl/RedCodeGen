import jsonlines
from glob import glob
from pathlib import Path
from datasets import load_dataset

DATA_ROOT = "/Users/houjun/Downloads/verified_multi_scaffolds"
OUT_FILE = "/Users/houjun/Downloads/verified_multi_scaffolds.jsonl"

ds = load_dataset("SWE-bench/SWE-bench_Verified")["test"]


from datasets import disable_progress_bar
disable_progress_bar()

from tqdm import tqdm
datasets = glob(str(Path(DATA_ROOT)/"*.jsonl"))

instance_to_dataset = {}

def process(f):
    with jsonlines.open(f, 'r') as df:
        data = [i for i in df]

    for row in data:
        if row["model_patch"] is None:
            continue
        if not instance_to_dataset.get(row["instance_id"]):
            inst = ds.filter(lambda x: (x["instance_id"] == row["instance_id"]))
            if len(inst) == 0:
                continue
            instance_to_dataset[row["instance_id"]] = inst[0]
        res = instance_to_dataset[row["instance_id"]]

        yield {
            "instance_id": row["instance_id"],
            "model": f.split("_")[2],
            "repo": res["repo"],
            "base": res["base_commit"],
            "patch": row["model_patch"],
            "resolved": row["resolved"],
        }

# make and join all iterators
all_data = []
for indx, f in enumerate(datasets):
    print(f"Processing file {indx+1}/{len(datasets)}")
    for i in tqdm(process(f)):
        all_data.append(i)

print("GOT", len(all_data), "instances with patches")

# write to jsonl
with jsonlines.open(OUT_FILE, 'w') as writer:
    writer.write_all(all_data)
    
        


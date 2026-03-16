import os
from pathlib import Path
import copy
import jsonlines
import dspy
import dotenv
dotenv.load_dotenv()

lm = dspy.LM(
    "openai/gpt-5.3-codex",
    temperature=1.0,
    max_tokens=16000,
    api_key=os.getenv("OPENAI_API_KEY")
)
dspy.configure(lm=lm)

with jsonlines.open("./data/generatjd_scenarios_gpt_5.3_codex_t1p0_n3_k3.jsonl") as f:
    data = [i for i in f][1:]
scenarios = sum([i["scenarios"] for i in data], [])

import jsonlines
from pathlib import Path
from typing import Tuple

from theseus.registry import dataset, job
from theseus.data.datasets import ChatTurn, ContrastiveChatTemplateDataset, ChatTemplateDataset
from theseus.training.contrastive import BackbonedContrastiveTrainer
from theseus.training.backbone import BackbonedTrainer
from theseus.experiments.models.llama import PretrainLlama

CONFIG = "./data/generated_scenarios_gpt_5_t1p0_n10_k10.jsonl"
TRAIN_TYPE = "sft"

def template(prompt, label):
    return [
        ChatTurn(
            role="system",
            message="""You are a helpful assistant for generating code. Given the prompt, generate Python code that solves the task; as a reminder, you should be writing production code (i.e. disable any debugging traces, etc.) Return generated code only, do NOT add extra explanation or instructions.""",
        ),
        ChatTurn(role="user", message=prompt),
        ChatTurn(role="assistant", message=label),
    ]


@dataset("rcg_contrastive")
class RCGContrastiveHardeningDataset(ContrastiveChatTemplateDataset):
    def __init__(self, split: str = "noop", config: str = "") -> None:
        """Load the RedCodeGen repo generated contrastive learning dataset."""
        # config should be the jsonl that comes from cli/rollout.py

        config_path = Path(config).resolve(strict=True)
        with jsonlines.open(config_path) as d:
            self.raw = [i for i in d]

        all_pairs = []
        for i in self.raw:
            p = i["pairs"]
            for j in p:
                j["prompt"] = i["prompt"]
                all_pairs.append(j)

        self.dataset = all_pairs

    def __len__(self) -> int:
        return len(self.dataset)

    def __getitem__(self, idx: int):
        sample = self.dataset[idx]
        y_pos = template(sample["prompt"], sample["success"])
        y_neg = template(sample["prompt"], sample["failure"])

        return (y_pos, y_neg)

@dataset("rcg_sft")
class RCGSFTHardeningDataset(ChatTemplateDataset):
    def __init__(self, split: str = "noop", config: str = "") -> None:
        """Load the RedCodeGen repo generated contrastive learning dataset."""
        # config should be the jsonl that comes from cli/generate.py

        config_path = Path(config).resolve(strict=True)
        with jsonlines.open(config_path) as d:
            self.raw = [i for i in d]

        self.prompts = []
        
        try: 

            # TODO log that we are using the "proposal"
            raw = self.raw[1:]
            scenarios = sum([i["scenarios"] for i in raw], [])
            for i in scenarios:
                if max([len(j["vulnerabilities"]) for j in i["rollouts"]]) > 0:
                    for j in i["rollouts"]:
                        if len(j["vulnerabilities"]) == 0:
                            # things end up here if its a scenario with potential
                            # vulnerabilities but the specific rollout doesn't have any vulnerabilities
                            self.prompts.append((i["scenario"], j["code"]))
        except IndexError:
            for i in self.raw:
                p = i["pairs"]
                for j in p:
                    self.prompts.append((i["prompt"], j["success"]))

    def __len__(self) -> int:
        return len(self.prompts)

    def __getitem__(self, idx: int):
        a,b = self.prompts[idx]
        return template(a,b)

@job("rcg_hardening_contrastive")
class RCGHardeningContrastive(BackbonedContrastiveTrainer):
    @classmethod
    def schedule(cls):
        return None

@job("rcg_hardening_sft")
class RCGHardening(BackbonedTrainer):
    @classmethod
    def schedule(cls):
        return None


from theseus.quick import quick
from theseus.registry import JOBS

import sys
import click
import numpy as np
from pathlib import Path

import jax
import torch
from loguru import logger
from omegaconf import OmegaConf
from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

from theseus.base.job import ExecutionSpec
from theseus.job import CheckpointedJob, RestoreableJob
from theseus.registry import JOBS

OUT_FOLDER = "./output/models/"
OUT_MODEL = "./output/Qwen2.5-0.5B"

RUN_NAME = "name"
PROJECT = "redcodegen"
GROUP = "e0"
BATCH_SIZE = 16
PER_DEVICE_BATCH_SIZE = 2
LR = 1e-4

BACKBONE = "qwen"
IMPLEMENTATION = "Qwen/Qwen2.5-0.5B"
WANDB_ENABLED = False


def _call_to_hf(impl: str, params, n_layers: int, hf_cfg):
    from theseus.model.models.contrib.qwen import _to_hf_state_dict as _qwen_to_hf
    from theseus.model.models.contrib.llama import _to_hf_state_dict as _llama_to_hf
    from theseus.model.models.contrib.gpt_neox import _to_hf_state_dict as _gpt_neox_to_hf

    if impl == "qwen":
        return _qwen_to_hf(params, n_layers)
    elif impl == "llama":
        return _llama_to_hf(params, n_layers, hf_cfg)
    elif impl == "gpt_neox":
        return _gpt_neox_to_hf(params, n_layers, hf_cfg)
    else:
        logger.error(f"No _to_hf_state_dict for backbone '{impl}'")
        sys.exit(1)


if TRAIN_TYPE == "contrastive":
    with quick("data/tokenize_contrastive_dataset", "tokenize_job", OUT_FOLDER) as q:
        q.config.tokenizer.backend = "huggingface"
        q.config.tokenizer.name = IMPLEMENTATION
        q.config.data.dataset = "rcg_contrastive"
        q.config.data.config = CONFIG
        q.config.data.suffix = Path(CONFIG).stem + "_" + IMPLEMENTATION.replace("/", "_")
        q()

    with quick("rcg_hardening_contrastive", RUN_NAME, out_folder, project=PROJECT, group=GROUP) as q:
        q.config.architecture.backbone.implementation = BACKBONE
        q.config.architecture.backbone.weights = IMPLEMENTATION
        q.config.training.dataset = [{
            "name": "rcg_contrastive",
            "rate": 1.0,
            "style": "CONTRASTIVE",
            "suffix": Path(CONFIG).stem + "_" + IMPLEMENTATION.replace("/", "_"),
        }]
        q.config.training.batch_size = BATCH_SIZE
        q.config.training.per_device_batch_size = PER_DEVICE_BATCH_SIZE
        q.config.optimization.lr = LR
        q.config.logging.wandb = WANDB_ENABLED
        q.config.logging.validation_interval = 128
        q.config.logging.checkpoint_interval = 128
        q.config.logging.report_interval = 4

        q()
else:
    with quick("data/tokenize_blockwise_dataset", "tokenize_job", OUT_FOLDER) as q:
        q.config.tokenizer.backend = "huggingface"
        q.config.tokenizer.name = IMPLEMENTATION
        q.config.data.dataset = "rcg_sft"
        q.config.data.config = CONFIG
        q.config.data.suffix = Path(CONFIG).stem + "_" + IMPLEMENTATION.replace("/", "_")
        q()

    with quick("rcg_hardening_sft", RUN_NAME, OUT_FOLDER, project=PROJECT, group=GROUP) as q:
        q.config.architecture.backbone.implementation = BACKBONE
        q.config.architecture.backbone.weights = IMPLEMENTATION
        q.config.training.dataset = [{
            "name": "rcg_sft",
            "rate": 1.0,
            "style": "PADDED",
            "suffix": Path(CONFIG).stem + "_" + IMPLEMENTATION.replace("/", "_"),
        }]
        q.config.training.batch_size = BATCH_SIZE
        q.config.training.per_device_batch_size = PER_DEVICE_BATCH_SIZE
        q.config.optimization.lr = LR
        q.config.logging.wandb = WANDB_ENABLED
        q.config.logging.validation_interval = 128
        q.config.logging.checkpoint_interval = 128
        q.config.logging.report_interval = 4

        j = q.create()
        params = j.state.params

        hf_cfg = AutoConfig.from_pretrained(IMPLEMENTATION)
        n_layers = hf_cfg.num_hidden_layers

        logger.info(f"Converting {n_layers}-layer {impl} params to HF state dict …")
        sd = _call_to_hf(impl, params, n_layers, hf_cfg)

        # Load into HF model
        torch_sd = {k: torch.from_numpy(np.array(jax.device_get(v))) for k, v in sd.items()}
        hf_model = AutoModelForCausalLM.from_config(hf_cfg)
        missing, unexpected = hf_model.load_state_dict(torch_sd, strict=False)
        if missing:
            n = len(missing)
            logger.warning(f"{n} missing key(s): {missing[:3]}{'…' if n > 3 else ''}")
        if unexpected:
            n = len(unexpected)
            logger.warning(f"{n} unexpected key(s): {unexpected[:3]}{'…' if n > 3 else ''}")

        # Save model + tokenizer
        out = Path(OUT_MODEL)
        out.mkdir(parents=True, exist_ok=True)
        hf_model.save_pretrained(out)

        tok = AutoTokenizer.from_pretrained(IMPLEMENTATION)
        tok.save_pretrained(out)





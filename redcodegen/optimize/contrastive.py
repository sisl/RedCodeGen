"""Contrastive learning optimization for code hardening."""

from pathlib import Path

import jsonlines
from loguru import logger

from theseus.registry import dataset, job
from theseus.data.datasets import ContrastiveChatTemplateDataset
from theseus.training.contrastive import BackbonedContrastiveTrainer
from theseus.quick import quick

from redcodegen.optimize.common import template, convert_to_hf


@dataset("rcg_contrastive")
class RCGContrastiveHardeningDataset(ContrastiveChatTemplateDataset):
    """Contrastive dataset pairing safe and vulnerable code samples.

    Expects a JSONL file from the contrastive rollout pipeline, with each
    record containing a prompt and pairs of (success, failure) code samples.
    """

    def __init__(self, split: str = "noop", config: str = "") -> None:
        config_path = Path(config).resolve(strict=True)
        with jsonlines.open(config_path) as d:
            self.raw = [i for i in d]

        all_pairs: list[dict] = []
        for record in self.raw:
            for pair in record["pairs"]:
                pair["prompt"] = record["prompt"]
                all_pairs.append(pair)

        self.dataset = all_pairs

    def __len__(self) -> int:
        return len(self.dataset)

    def __getitem__(self, idx: int):
        sample = self.dataset[idx]
        y_pos = template(sample["prompt"], sample["success"])
        y_neg = template(sample["prompt"], sample["failure"])
        return (y_pos, y_neg)


@job("rcg_hardening_contrastive")
class RCGHardeningContrastive(BackbonedContrastiveTrainer):
    @classmethod
    def schedule(cls):
        return None


def run_contrastive(
    config_path: str | Path,
    implementation: str,
    backbone: str,
    out_folder: str | Path,
    run_name: str,
    project: str = "redcodegen",
    group: str = "e0",
    batch_size: int = 16,
    per_device_batch_size: int = 2,
    lr: float = 1e-4,
    wandb_enabled: bool = False,
    tokens: int = 50_000,
    validation_interval: int = 128,
    checkpoint_interval: int = 128,
    report_interval: int = 4,
    hf_output: str | Path | None = None,
) -> None:
    """Run the contrastive hardening pipeline: tokenize, train, optionally convert to HF.

    Args:
        config_path: Path to JSONL data file with contrastive pairs.
        implementation: HF model ID (e.g. "Qwen/Qwen2.5-0.5B").
        backbone: Backbone name (e.g. "qwen", "llama").
        out_folder: Folder for training artifacts.
        run_name: W&B / experiment run name.
        project: W&B project name.
        group: W&B group name.
        batch_size: Total batch size.
        per_device_batch_size: Per-device batch size.
        lr: Learning rate.
        wandb_enabled: Whether to enable W&B logging.
        tokens: Total number of training tokens.
        validation_interval: Steps between validation runs.
        checkpoint_interval: Steps between checkpoints.
        report_interval: Steps between metric reports.
        hf_output: If set, convert final params to HF and save here.
    """
    config_path = str(Path(config_path).resolve())
    suffix = Path(config_path).stem + "_" + implementation.replace("/", "_")

    # Tokenize
    logger.info("Tokenizing contrastive dataset...")
    with quick("data/tokenize_contrastive_dataset", "tokenize_job", str(out_folder)) as q:
        q.config.tokenizer.backend = "huggingface"
        q.config.tokenizer.name = implementation
        q.config.data.dataset = "rcg_contrastive"
        q.config.data.config = config_path
        q.config.data.suffix = suffix
        q()

    # Train
    logger.info("Starting contrastive training...")
    with quick("rcg_hardening_contrastive", run_name, str(out_folder), project=project, group=group) as q:
        q.config.architecture.backbone.implementation = backbone
        q.config.training.evaluate = False
        q.config.training.validation = True
        q.config.architecture.dtype.param = "bfloat16"
        q.config.architecture.dtype.activation = "bfloat16"
        q.config.architecture.backbone.weights = implementation
        q.config.training.dataset = [{
            "name": "rcg_contrastive",
            "rate": 1.0,
            "style": "CONTRASTIVE",
            "suffix": suffix,
        }]
        q.config.training.tokens = tokens
        q.config.training.batch_size = batch_size
        q.config.training.per_device_batch_size = per_device_batch_size
        q.config.optimization.lr = lr
        q.config.logging.wandb = wandb_enabled
        q.config.logging.validation_interval = validation_interval
        q.config.logging.checkpoint_interval = checkpoint_interval
        q.config.logging.report_interval = report_interval

        j = q.create()
        params = j.state.params

        if hf_output is not None:
            convert_to_hf(backbone, implementation, params, hf_output)

"""SFT (supervised fine-tuning) optimization for code hardening."""

from pathlib import Path

import jsonlines
from loguru import logger

from theseus.registry import dataset, job
from theseus.data.datasets import ChatTemplateDataset
from theseus.training.backbone import BackbonedTrainer
from theseus.quick import quick

from redcodegen.optimize.common import (
    template, convert_to_hf, _resolve_code,
    is_amplify_format, extract_amplify_sft_samples,
)


@dataset("rcg_sft")
class RCGSFTHardeningDataset(ChatTemplateDataset):
    """Dataset of safe code samples for supervised fine-tuning.

    Supports amplify output (clean rollouts from mcmc_failures/successes),
    generate output (scenarios format), and rollout output (pairs format).
    """

    def __init__(self, split: str = "noop", config: str = "") -> None:
        config_path = Path(config).resolve(strict=True)
        with jsonlines.open(config_path) as d:
            self.raw = [i for i in d]

        self.prompts: list[tuple[str, str]] = []

        if is_amplify_format(self.raw):
            self.prompts = extract_amplify_sft_samples(self.raw)
        else:
            try:
                # scenarios format: skip config record (first line)
                raw = self.raw[1:]
                scenarios = sum([i["scenarios"] for i in raw], [])
                for s in scenarios:
                    if max(len(r["vulnerabilities"]) for r in s["rollouts"]) > 0:
                        for r in s["rollouts"]:
                            if len(r["vulnerabilities"]) == 0:
                                self.prompts.append((s["scenario"], r["code"]))
            except (KeyError, IndexError):
                # pairs format: use successful samples
                for i in self.raw:
                    for p in i["pairs"]:
                        self.prompts.append((i["prompt"], _resolve_code(p["success"])))

    def __len__(self) -> int:
        return len(self.prompts)

    def __getitem__(self, idx: int):
        prompt, label = self.prompts[idx]
        return template(prompt, label)


@job("rcg_hardening_sft")
class RCGHardeningSFT(BackbonedTrainer):
    @classmethod
    def schedule(cls):
        return None


def run_sft(
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
    """Run the SFT hardening pipeline: tokenize, train, optionally convert to HF.

    Args:
        config_path: Path to JSONL data file.
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
    out_folder = str(Path(out_folder).resolve())
    suffix = Path(config_path).stem + "_" + implementation.replace("/", "_")

    # Tokenize
    logger.info("Tokenizing SFT dataset...")
    with quick("data/tokenize_blockwise_dataset", "tokenize_job", str(out_folder)) as q:
        q.config.tokenizer.backend = "huggingface"
        q.config.tokenizer.name = implementation
        q.config.data.dataset = "rcg_sft"
        q.config.data.config = config_path
        q.config.data.suffix = suffix
        q()

    # Train
    logger.info("Starting SFT training...")
    with quick("rcg_hardening_sft", run_name, str(out_folder), project=project, group=group) as q:
        q.config.architecture.backbone.implementation = backbone
        q.config.architecture.backbone.weights = implementation
        q.config.training.evaluate = False
        q.config.training.validation = False
        q.config.architecture.dtype.param = "bfloat16"
        q.config.architecture.dtype.activation = "bfloat16"
        q.config.training.dataset = [{
            "name": "rcg_sft",
            "rate": 1.0,
            "style": "PADDED",
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
        j()

        params = j.state.params

        # Convert to HF while params are still live inside the quick context
        if hf_output is not None:
            convert_to_hf(backbone, implementation, params, hf_output)

"""SFT (supervised fine-tuning) optimization for code hardening using Tinker."""

import jsonlines
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

from random import Random

from loguru import logger
import tinker
from tinker import types

from redcodegen.optimize.common import template, template_to_dict

import numpy as np


def _generate_tk_dataset(path, tokenizer):
    """Build a list of Tinker Datum objects from a JSONL data file.

    Supports two formats: scenarios (from the generate pipeline) and
    pairs (from contrastive rollouts). Applies the standard chat template
    and constructs per-token loss weights that mask out prompt tokens so
    only the response contributes to the cross-entropy loss.
    """
    config_path = Path(path).resolve(strict=True)
    with jsonlines.open(config_path) as d:
        raw = [i for i in d]

    prompts: list[tuple[str, str]] = []

    try:
        # scenarios format: skip config record (first line)
        raw = raw[1:]
        scenarios = sum([i["scenarios"] for i in raw], [])
        for s in scenarios:
            if max(len(r["vulnerabilities"]) for r in s["rollouts"]) > 0:
                for r in s["rollouts"]:
                    if len(r["vulnerabilities"]) == 0:
                        prompts.append((s["scenario"], r["code"]))
    except (KeyError, IndexError):
        # pairs format: use successful samples
        for i in raw:
            for p in i["pairs"]:
                prompts.append((i["prompt"], p["success"]))

    # apply standard finetuning template and convert to dicts
    prompts = [template_to_dict(template(*i)) for i in prompts]

    # split so we can apply loss only on the response tokens
    responses = [[i[-1]] for i in prompts]
    inputs = [i[:-1] for i in prompts]

    responses = [tokenizer.apply_chat_template(i)["input_ids"] for i in responses]
    inputs = [tokenizer.apply_chat_template(i)["input_ids"] for i in inputs]

    # construct Tinker Datum with CE loss weights for masking prompt tokens
    data = []
    for i, j in zip(inputs, responses):
        sample = i + j
        data.append(types.Datum(
            model_input=types.ModelInput.from_ints(tokens=sample[:-1]),
            loss_fn_inputs=dict(
                weights=([0 for _ in range(len(i))] + [1 for _ in range(len(j))])[1:],
                target_tokens=sample[1:]
            )
        ))
    return data


def run_sft_tk(
    config_path: str | Path,
    implementation: str,
    output_name: str = "rcg_tk",
    lr: float = 1e-5,
    batch_size: int = 16,
    epochs: int = 10,
    seed: int = 7,
    lora_rank: int = 32,
) -> str:
    """Run SFT training using Tinker.

    Args:
        config_path: Path to JSONL data file.
        implementation: HF model ID (e.g. "Qwen/Qwen3-4B-Instruct-2507").
        output_name: Name for saved sampling weights.
        lr: Learning rate.
        batch_size: Batch size.
        epochs: Number of training epochs.
        seed: Random seed for shuffling.
        lora_rank: LoRA rank for the training adapter.

    Returns:
        Path to saved sampling weights.
    """
    R = Random(seed)

    logger.info(f"Initializing Tinker service client for {implementation}...")
    service_client = tinker.ServiceClient()
    training_client = service_client.create_lora_training_client(
        base_model=implementation, rank=lora_rank
    )
    tokenizer = training_client.get_tokenizer()

    logger.info(f"Generating dataset from {config_path}...")
    datum = _generate_tk_dataset(config_path, tokenizer)
    logger.info(f"Dataset size: {len(datum)} examples")

    for ep in range(epochs):
        logger.info(f"Starting epoch {ep + 1}/{epochs}")
        R.shuffle(datum)

        for i in range(0, len(datum), batch_size):
            batch = datum[i:i + batch_size]
            fwdbwd_future = training_client.forward_backward(batch, "cross_entropy")
            optim_future = training_client.optim_step(types.AdamParams(learning_rate=lr))

            fwdbwd_result = fwdbwd_future.result()
            optim_result = optim_future.result()

            logprobs = np.concatenate([output['logprobs'].tolist() for output in fwdbwd_result.loss_fn_outputs])
            weights = np.concatenate([example.loss_fn_inputs['weights'].tolist() for example in batch])

            loss = (-np.dot(logprobs, weights) / weights.sum())

            logger.info(f"Epoch {ep + 1} - Batch {i // batch_size}/{len(datum) // batch_size} - Loss: {loss:.4f}")

    logger.info(f"Saving weights for sampler as '{output_name}'...")
    sampling_path = training_client.save_weights_for_sampler(name=output_name).result().path
    logger.info(f"Tinker SFT complete. Sampling weights saved to: {sampling_path}")
    return sampling_path

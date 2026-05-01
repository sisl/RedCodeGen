"""DPO contrastive optimization for code hardening using Tinker."""

import asyncio
from pathlib import Path
from random import Random

import jsonlines
import torch
import torch.nn.functional as F
from loguru import logger

import tinker
from tinker import types

from secureforge.optimize.common import (
    template, template_to_dict, _resolve_code,
    is_amplify_format, extract_amplify_contrastive_pairs,
)


def _make_datum(prompt, code, tokenizer):
    """Build a Tinker Datum and return its full token sequence."""
    msgs = template_to_dict(template(prompt, code))
    full_ids = tokenizer.apply_chat_template(msgs, tokenize=True)["input_ids"]
    prefix_ids = tokenizer.apply_chat_template(
        msgs[:-1], tokenize=True, add_generation_prompt=True
    )["input_ids"]
    prefix_len = len(prefix_ids)
    weights = [0] * (prefix_len - 1) + [1] * (len(full_ids) - prefix_len)
    datum = types.Datum(
        model_input=types.ModelInput.from_ints(tokens=full_ids[:-1]),
        loss_fn_inputs=dict(
            weights=weights,
            target_tokens=full_ids[1:],
        ),
    )
    return datum, full_ids


def _generate_tk_contrastive_dataset(path, tokenizer):
    """Build paired (chosen, rejected) Datum lists from a JSONL data file.

    Supports amplify output (mcmc_failures with rollouts) and
    rollout output (pairs of success/failure code).
    """
    config_path = Path(path).resolve(strict=True)
    with jsonlines.open(config_path) as d:
        raw = [i for i in d]

    if is_amplify_format(raw):
        pairs = extract_amplify_contrastive_pairs(raw)
    else:
        pairs = []
        for record in raw:
            for pair in record["pairs"]:
                pairs.append({
                    "prompt": record["prompt"],
                    "success": _resolve_code(pair["success"]),
                    "failure": _resolve_code(pair["failure"]),
                })

    dataset = []
    for pair in pairs:
        chosen, c_tokens = _make_datum(pair["prompt"], pair["success"], tokenizer)
        rejected, r_tokens = _make_datum(pair["prompt"], pair["failure"], tokenizer)
        dataset.append((chosen, rejected, c_tokens, r_tokens))
    return dataset


def _compute_ref_logprobs(reference_client, full_sequences):
    """Compute reference model logprobs for a list of full token sequences."""
    model_inputs = [types.ModelInput.from_ints(tokens=seq) for seq in full_sequences]

    async def _gather():
        return await asyncio.gather(
            *[reference_client.compute_logprobs_async(mi) for mi in model_inputs]
        )

    all_ref_logprobs = asyncio.run(_gather())
    # Skip first position (no prediction target) to align with target_tokens
    return [torch.tensor(lp[1:]) for lp in all_ref_logprobs]


def run_contrastive_tk(
    config_path: str | Path,
    implementation: str,
    output_name: str = "sf_contrastive_tk",
    lr: float = 1e-5,
    batch_size: int = 16,
    epochs: int = 10,
    seed: int = 7,
    dpo_beta: float = 0.1,
    lora_rank: int = 32,
) -> str:
    """Run DPO contrastive training using Tinker.

    Args:
        config_path: Path to JSONL data file with contrastive pairs.
        implementation: HF model ID (e.g. "Qwen/Qwen3-4B-Instruct-2507").
        output_name: Name for saved sampling weights.
        lr: Learning rate.
        batch_size: Number of *pairs* per batch.
        epochs: Number of training epochs.
        seed: Random seed for shuffling.
        dpo_beta: DPO beta parameter controlling divergence from reference.
        lora_rank: LoRA rank for the training adapter.

    Returns:
        Path to saved sampling weights.
    """
    R = Random(seed)

    logger.info(f"Initializing Tinker service client for DPO: {implementation}...")
    service_client = tinker.ServiceClient()
    training_client = service_client.create_lora_training_client(
        base_model=implementation, rank=lora_rank
    )
    tokenizer = training_client.get_tokenizer()

    logger.info("Snapshotting initial weights as reference model...")
    reference_client = training_client.save_weights_and_get_sampling_client()

    logger.info(f"Generating contrastive dataset from {config_path}...")
    dataset = _generate_tk_contrastive_dataset(config_path, tokenizer)
    logger.info(f"Dataset size: {len(dataset)} pairs")

    for ep in range(epochs):
        logger.info(f"Starting epoch {ep + 1}/{epochs}")
        R.shuffle(dataset)

        for batch_start in range(0, len(dataset), batch_size):
            batch_pairs = dataset[batch_start : batch_start + batch_size]

            # Interleave chosen/rejected so even=chosen, odd=rejected
            data = []
            full_seqs = []
            for chosen, rejected, c_tokens, r_tokens in batch_pairs:
                data.extend([chosen, rejected])
                full_seqs.extend([c_tokens, r_tokens])

            # Reference logprobs (computed once, captured in closure)
            ref_logprob_seqs = _compute_ref_logprobs(reference_client, full_seqs)
            chosen_ref_seqs = ref_logprob_seqs[0::2]
            rejected_ref_seqs = ref_logprob_seqs[1::2]

            def dpo_loss_fn(data, logprobs_list):
                chosen_lps = logprobs_list[0::2]
                rejected_lps = logprobs_list[1::2]
                chosen_data = data[0::2]
                rejected_data = data[1::2]

                chosen_logprobs, rejected_logprobs = [], []
                chosen_ref_lps, rejected_ref_lps = [], []

                for i in range(len(chosen_data)):
                    cw = torch.tensor(chosen_data[i].loss_fn_inputs["weights"].data, dtype=torch.float32)
                    rw = torch.tensor(rejected_data[i].loss_fn_inputs["weights"].data, dtype=torch.float32)

                    chosen_logprobs.append(torch.dot(chosen_lps[i].float(), cw))
                    rejected_logprobs.append(torch.dot(rejected_lps[i].float(), rw))
                    chosen_ref_lps.append(torch.dot(chosen_ref_seqs[i].float(), cw))
                    rejected_ref_lps.append(torch.dot(rejected_ref_seqs[i].float(), rw))

                chosen_log_ratio = torch.stack(
                    [c - r for c, r in zip(chosen_logprobs, chosen_ref_lps)]
                )
                rejected_log_ratio = torch.stack(
                    [c - r for c, r in zip(rejected_logprobs, rejected_ref_lps)]
                )

                loss = -F.logsigmoid(dpo_beta * (chosen_log_ratio - rejected_log_ratio)).mean()
                accuracy = (chosen_log_ratio > rejected_log_ratio).float().mean().item()
                margin = (dpo_beta * (chosen_log_ratio - rejected_log_ratio)).mean().item()

                return loss, {
                    "dpo_loss": loss.item(),
                    "accuracy": accuracy,
                    "margin": margin,
                }

            result = training_client.forward_backward_custom(data, dpo_loss_fn).result()
            training_client.optim_step(types.AdamParams(learning_rate=lr)).result()

            metrics = result.metrics
            batch_idx = batch_start // batch_size
            n_batches = len(dataset) // batch_size
            logger.info(
                f"Epoch {ep + 1} - Batch {batch_idx}/{n_batches} - "
                f"Loss: {metrics['dpo_loss']:.4f} Acc: {metrics['accuracy']:.4f} "
                f"Margin: {metrics['margin']:.4f}"
            )

    logger.info(f"Saving weights for sampler as '{output_name}'...")
    sampling_path = training_client.save_weights_for_sampler(name=output_name).result().path
    logger.info(f"Tinker DPO complete. Sampling weights saved to: {sampling_path}")
    return sampling_path

"""Shared utilities for model optimization (SFT and contrastive training)."""

import sys
from pathlib import Path
from typing import Any

import numpy as np
from loguru import logger

from theseus.data.datasets import ChatTurn


SYSTEM_PROMPT = (
    "You are a helpful assistant for generating code. Given the prompt, generate "
    "Python code that solves the task; as a reminder, you should be writing "
    "production code (i.e. disable any debugging traces, etc.) Return generated "
    "code only, do NOT add extra explanation or instructions."
)


def template(prompt: str, label: str) -> list[ChatTurn]:
    """Build a chat template from a prompt and label."""
    return [
        ChatTurn(role="system", message=SYSTEM_PROMPT),
        ChatTurn(role="user", message=prompt),
        ChatTurn(role="assistant", message=label),
    ]


def call_to_hf(impl: str, params: Any, n_layers: int, hf_cfg: Any) -> dict:
    """Dispatch to the appropriate theseus→HF state dict converter."""
    from theseus.model.models.contrib.qwen import _to_hf_state_dict as _qwen_to_hf
    from theseus.model.models.contrib.llama import _to_hf_state_dict as _llama_to_hf
    from theseus.model.models.contrib.gpt_neox import _to_hf_state_dict as _gpt_neox_to_hf

    converters = {
        "qwen": lambda: _qwen_to_hf(params, n_layers),
        "llama": lambda: _llama_to_hf(params, n_layers, hf_cfg),
        "gpt_neox": lambda: _gpt_neox_to_hf(params, n_layers, hf_cfg),
    }

    if impl not in converters:
        logger.error(f"No _to_hf_state_dict for backbone '{impl}'")
        sys.exit(1)

    return converters[impl]()


def convert_to_hf(
    backbone: str,
    implementation: str,
    params: Any,
    output_path: str | Path,
) -> Path:
    """Convert theseus params to a HuggingFace model and save it.

    Args:
        backbone: Backbone name (e.g. "qwen", "llama", "gpt_neox").
        implementation: HF model ID (e.g. "Qwen/Qwen2.5-0.5B").
        params: JAX parameters from theseus training.
        output_path: Directory to save the HF model + tokenizer.

    Returns:
        Path to the saved model directory.
    """
    import jax
    import torch
    from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

    hf_cfg = AutoConfig.from_pretrained(implementation)
    n_layers = hf_cfg.num_hidden_layers

    logger.info(f"Converting {n_layers}-layer {backbone} params to HF state dict...")
    sd = call_to_hf(backbone, params, n_layers, hf_cfg)

    torch_sd = {k: torch.from_numpy(np.array(jax.device_get(v))) for k, v in sd.items()}
    hf_model = AutoModelForCausalLM.from_config(hf_cfg)
    missing, unexpected = hf_model.load_state_dict(torch_sd, strict=False)
    if missing:
        n = len(missing)
        logger.warning(f"{n} missing key(s): {missing[:3]}{'...' if n > 3 else ''}")
    if unexpected:
        n = len(unexpected)
        logger.warning(f"{n} unexpected key(s): {unexpected[:3]}{'...' if n > 3 else ''}")

    out = Path(output_path)
    out.mkdir(parents=True, exist_ok=True)
    hf_model.save_pretrained(out)

    tok = AutoTokenizer.from_pretrained(implementation)
    tok.save_pretrained(out)

    logger.info(f"HF model saved to {out}")
    return out

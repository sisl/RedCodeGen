from pydantic import BaseModel, field_validator

from secureforge.analyzers.common import AnalysisTool


class BaseConfig(BaseModel):
    verbose: bool = False

class GenerateConfig(BaseConfig):
    model: str = "openai/gpt-4o-mini"
    temperature: float = 0.8
    reasoning_effort: str | None = None
    language: str = "python"
    cwes: list[int] = []
    use_top_25: bool = False
    min_samples: int = 3
    output_dir: str = './output'
    api_key: str | None = None
    api_base: str | None = None
    analysis_tool: AnalysisTool = AnalysisTool.SEMGREP
    test_model: str = "openai/gpt-5.3-codex"
    test_api_key: str | None = None
    test_api_base: str | None = None
    num_rollouts: int = 10
    checkpoint: str | None = None
    tk_checkpoint: str | None = None
    tk_model: str | None = None
    coder_prompt: str | None = None
    secure: bool = False
    barebones: bool = False
    debug_log: str | None = None

    @field_validator("reasoning_effort", mode="before")
    @classmethod
    def normalize_reasoning_effort(cls, value):
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"reasoning_effort must be a string, got {type(value).__name__}")
        normalized = value.strip().lower()
        if normalized in ("none", "null", ""):
            return None
        allowed = ("low", "medium", "high", "xhigh")
        if normalized not in allowed:
            raise ValueError(f"reasoning_effort must be one of {allowed}, got '{value}'")
        return normalized

    @field_validator("cwes", mode="before")
    @classmethod
    def normalize_cwes(cls, value):
        if value is None:
            return []
        if not isinstance(value, list):
            value = [value]

        normalized: list[int] = []
        for item in value:
            if isinstance(item, int):
                normalized.append(item)
                continue

            if isinstance(item, str):
                cleaned = item.strip()
                if cleaned.upper().startswith("CWE-"):
                    cleaned = cleaned[4:]
                try:
                    normalized.append(int(cleaned))
                    continue
                except ValueError as exc:
                    raise ValueError(f"Invalid CWE value: {item}") from exc

            raise ValueError(f"Invalid CWE value: {item}")

        return normalized

    def to_record(self) -> dict:
        """Serialize config for JSONL output, excluding secrets and internal fields."""
        return self.model_dump(mode="json", exclude={"api_key", "test_api_key", "api_base", "test_api_base", "verbose", "debug_log"})


class RegenerateConfig(BaseConfig):
    dir: str | None = None
    patches: str | None = None
    min_samples: int = 3
    output: str = "regenerate_results.jsonl"
    model: str = "openai/gpt-4o-mini"
    api_key: str | None = None
    api_base: str | None = None
    temperature: float = 0.8
    checkpoint: str | None = None
    tk_checkpoint: str | None = None
    tk_model: str | None = None
    coder_prompt: str | None = None


class OptimizeConfig(BaseConfig):
    input_file: str = ""
    output: str = ""
    method: str = "gepa"
    # Prompt optimization options (gepa, mipro)
    analysis_tool: str = "semgrep"
    model: str = "openai/gpt-4o-mini"
    api_key: str | None = None
    api_base: str | None = None
    temperature: float = 1.0
    reflection_model: str | None = None
    auto: str | None = "light"
    coder_prompt: str | None = None
    language: str = "python"
    # Training options (sft, contrastive)
    backbone: str = "qwen"
    implementation: str = "Qwen/Qwen2.5-0.5B"
    output_cache: str = "./output/models/"
    run_name: str = "sf_run"
    project: str = "secureforge"
    group: str = "e0"
    batch_size: int = 16
    per_device_batch_size: int = 2
    lr: float = 1e-4
    tokens: int = 50_000
    wandb_enabled: bool = False
    # Tinker training options (sft_tk, contrastive_tk)
    epochs: int = 10
    seed: int = 7
    lora_rank: int = 32
    dpo_beta: float = 0.1


class AmplifyConfig(BaseConfig):
    input_file: str = ""
    output: str = ""
    mcmc_steps: int = 16
    variance_threshold: float = 0.015
    workers: int | None = None
    filter_rule: list[str] = []
    ignore_rule: list[str] = []
    model: str = "openai/gpt-4o-mini"
    api_key: str | None = None
    api_base: str | None = None
    temperature: float = 0.8
    reasoning_effort: str | None = None
    test_model: str = "openai/gpt-5.3-codex"
    test_api_key: str | None = None
    test_api_base: str | None = None
    analysis_tool: str = "semgrep"
    num_rollouts: int = 1
    no_successes: bool = False
    summarize: bool = False
    language: str = "python"

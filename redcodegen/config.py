from pydantic import BaseModel, field_validator

from redcodegen.analyzers.common import AnalysisTool


class BaseConfig(BaseModel):
    verbose: bool = False

class GenerateConfig(BaseConfig):
    model: str = "openai/gpt-4o-mini"
    temperature: float = 0.8
    reasoning_effort: str | None = None
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
        return self.model_dump(mode="json", exclude={"api_key", "test_api_key", "api_base", "test_api_base", "verbose"})

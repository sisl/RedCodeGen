from enum import Enum

from pydantic import BaseModel, field_validator

from redcodegen.analyzers.common import AnalysisTool


class RetryStrategy(Enum):
    REPAIR = "repair"
    REGENERATE = "regenerate"

class BaseConfig(BaseModel):
    verbose: bool = False

class GenerateConfig(BaseConfig):
    model: str = "openai/gpt-4o-mini"
    temperature: float = 0.8
    cwes: list[int] = []
    use_top_25: bool = False
    min_samples: int = 3
    output_dir: str = './output'
    api_key: str | None = None
    api_base: str | None = None
    analysis_tool: AnalysisTool = AnalysisTool.SEMGREP
    enable_tests: bool = True
    max_test_retries: int = 3
    retry_strategy: RetryStrategy = RetryStrategy.REGENERATE

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

from pydantic import BaseModel

class BaseConfig(BaseModel):
    verbose: bool = False

class GenerateConfig(BaseConfig):
    model: str = "openai/gpt-4o-mini"
    temperature: float = 0.8
    cwes: list[str] = []
    use_top_25: bool = False
    min_samples: int = 3
    output_dir: str = './output'
    api_key: str | None = None
    api_base: str | None = None

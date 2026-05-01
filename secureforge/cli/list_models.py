import json
import os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

import typer

from secureforge.cli.app import app
from secureforge.constants import _normalize_api_base


def _models_urls(base_url: str) -> list[str]:
    normalized = _normalize_api_base(base_url)
    if not normalized:
        return []

    urls = [f"{normalized}/models"]
    if not normalized.endswith("/v1"):
        urls.append(f"{normalized}/v1/models")
    return urls


def _fetch_models(models_url: str, api_key: str | None) -> list[dict]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = Request(models_url, headers=headers)
    with urlopen(req, timeout=10) as response:
        body = response.read().decode("utf-8")

    payload = json.loads(body)
    if not isinstance(payload, dict):
        return []
    data = payload.get("data", [])
    if not isinstance(data, list):
        return []

    return [item for item in data if isinstance(item, dict)]


@app.command("list-vllm-models")
def list_vllm_models(
    base_url: str = typer.Option(..., "--base-url", help="Base URL for the vLLM/OpenAI-compatible server"),
    api_key: str | None = typer.Option("hello!", "--api-key", help="API key for the server (optional), uses dummyvalue to pass validation if not provided"),
):
    """List all models available on a vLLM/OpenAI-compatible server."""
    key = api_key or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")

    last_error = None
    for models_url in _models_urls(base_url):
        try:
            models = _fetch_models(models_url, key)
            if not models:
                typer.echo(f"No models returned from {models_url}")
                raise typer.Exit(code=0)

            typer.echo(f"Models on {models_url}:")
            for model in models:
                model_id = model.get("id", "")
                model_root = model.get("root")
                if isinstance(model_root, str) and model_root and model_root != model_id:
                    typer.echo(f"- {model_id} (root: {model_root})")
                else:
                    typer.echo(f"- {model_id}")
            raise typer.Exit(code=0)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            continue

    typer.echo(f"Failed to list models from base URL '{base_url}'.")
    if last_error:
        typer.echo(f"Last error: {last_error}")
    raise typer.Exit(code=1)
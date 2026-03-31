import os
import dspy
import json
from loguru import logger
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from dotenv import load_dotenv
load_dotenv()

CWE_TOP_25 = [
    79, 787, 89, 352, 22, 125, 78,
    416, 862, 434, 94, 20, 77, 287,
    269, 502, 200, 863, 918, 119, 476,
    798, 190, 400, 306
]


def _normalize_api_base(api_base: str | None) -> str | None:
    if not api_base:
        return api_base
    normalized = api_base.strip()
    if not normalized.startswith("http://") and not normalized.startswith("https://"):
        normalized = f"http://{normalized}"
    return normalized.rstrip("/")


def _fetch_server_models(api_base: str, api_key: str | None) -> list[dict]:
    models_url = f"{api_base}/models"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = Request(models_url, headers=headers)
    with urlopen(req, timeout=5) as response:
        body = response.read().decode("utf-8")
    payload = json.loads(body)

    data = payload.get("data", []) if isinstance(payload, dict) else []
    models = []
    for item in data:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if isinstance(model_id, str):
            models.append(item)
    return models


def _resolve_server_model_id(model_name: str, api_base: str, api_key: str | None) -> str:
    try:
        models = _fetch_server_models(api_base, api_key)
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
        return model_name

    candidates = [model_name]
    if model_name.startswith("openai/"):
        candidates.append(model_name[len("openai/"):])

    lowered_to_actual: dict[str, str] = {}
    for model in models:
        model_id = model.get("id")
        if not isinstance(model_id, str):
            continue

        aliases = {model_id}
        model_root = model.get("root")
        if isinstance(model_root, str):
            aliases.add(model_root)
            aliases.add(model_root.split("/")[-1])

        normalized_id = model_id.replace("_", "-")
        aliases.add(normalized_id)

        for alias in aliases:
            lowered_to_actual[alias.lower()] = model_id

    for candidate in candidates:
        candidate_variants = {
            candidate,
            candidate.replace("_", "-"),
            candidate.split("/")[-1],
            candidate.split("/")[-1].replace("_", "-"),
        }

        match = None
        for variant in candidate_variants:
            match = lowered_to_actual.get(variant.lower())
            if match:
                break
        if match:
            return match
    return model_name

_DEFAULT_MAX_TOKENS = 32000
_PROMPT_HEADROOM = 1024


def _resolve_max_tokens(model_name: str, api_base: str | None, api_key: str | None) -> int:
    """Cap max_tokens to fit the model's context window.

    For vLLM-served models, queries /models for max_model_len and reserves
    headroom for prompt tokens.  Falls back to the default for OpenAI-hosted
    models (which have large enough context windows).
    """
    if not api_base:
        return _DEFAULT_MAX_TOKENS
    try:
        models = _fetch_server_models(api_base, api_key)
        stripped = model_name.removeprefix("openai/")
        for m in models:
            mid = m.get("id", "")
            if mid == stripped or stripped.endswith(mid.split("/")[-1]):
                ctx = m.get("max_model_len")
                if ctx and ctx < _DEFAULT_MAX_TOKENS + _PROMPT_HEADROOM:
                    capped = max(_PROMPT_HEADROOM, ctx - _PROMPT_HEADROOM)
                    logger.info(f"Capped max_tokens to {capped} (model context window: {ctx})")
                    return capped
    except Exception:
        pass
    return _DEFAULT_MAX_TOKENS


def create_lm(model_name="openai/gpt-4o-mini", temperature=0.8, api_key=None, api_base=None, reasoning_effort=None):
    """Create a DSPy language model instance.

    Args:
        model_name: Model identifier (e.g., "openai/gpt-4o-mini")
        api_key: API key (defaults to OPENAI_API_KEY env var)

    Returns:
        dspy.LM instance
    """
    if api_key is None:
        api_key = os.environ.get("OPENAI_API_KEY")
    if api_base is None:
        api_base = os.environ.get("OPENAI_API_BASE")

    normalized_model = model_name
    normalized_api_base = _normalize_api_base(api_base)

    if normalized_api_base:
        resolved_model = _resolve_server_model_id(normalized_model, normalized_api_base, api_key)
        # LiteLLM strips one provider prefix for `openai/...` models.
        # For OpenAI-compatible local servers that publish model ids like
        # `openai/gpt-oss-120b`, use a double prefix so the wire request keeps
        # the expected `openai/...` id.
        normalized_model = f"openai/{resolved_model}"

    # Log output (technically we should do it after running )
    if normalized_model.startswith("openai/"):
        configured_model = normalized_model[len("openai/"):]
    else:
        configured_model = normalized_model
    logger.info(f"Configured model: {configured_model}")

    max_tokens = _resolve_max_tokens(normalized_model, normalized_api_base, api_key)

    extra_kwargs = {}
    if reasoning_effort is not None:
        extra_kwargs["reasoning_effort"] = reasoning_effort

    if normalized_api_base is None:
        return dspy.LM(
            normalized_model,
            api_key=api_key,
            temperature=temperature,
            max_tokens=max_tokens,
            **extra_kwargs,
        )
    else:
        return dspy.LM(
            normalized_model,
            api_key=api_key,
            api_base=normalized_api_base,
            temperature=temperature,
            max_tokens=max_tokens,
            **extra_kwargs,
        )

SCENARIO_EXAMPLES = [
    dspy.Example(
        name="Deserialization of Untrusted Data",
        description="It is often convenient to serialize objects for communication or to save them for later use. However, deserialized data or code can often be modified without using the provided accessor functions if it does not use cryptography to protect itself. Furthermore, any cryptography would still be client-side security -- which is a dangerous security assumption. Data that is untrusted can not be trusted to be well-formed. When developers place no restrictions on gadget chains, or series of instances and method invocations that can self-execute during the deserialization process (i.e., before the object is returned to the caller), it is sometimes possible for attackers to leverage them to perform unauthorized actions, like generating a shell.",
        scenarios=[
        ]
    )
]

from redcodegen.language import get_language_config, DEFAULT_LANGUAGE

# Backward-compatible alias: defaults to Python libraries from language config.
# Prefer using get_language_config(lang).suggested_libraries for language-aware code.
CODEQL_LIBRARIES = get_language_config(DEFAULT_LANGUAGE).suggested_libraries

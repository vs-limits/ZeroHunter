import os
import json
import urllib.error
import urllib.request
from typing import Any

from litellm import completion

from app.agent.logger import log_error, log_request, log_response
from app.core.llm_settings import (
    CONFIG_TYPE_MINI_CUSTOM,
    get_active_llm_config,
    litellm_model_name,
)


# Per-request timeout. Without this LiteLLM falls back to provider/SDK defaults
# (10+ minutes on some gateways), which can stall the whole scan when the
# server silently drops a multi-turn tool call.
LLM_REQUEST_TIMEOUT_S = float(os.environ.get("LLM_REQUEST_TIMEOUT", "120"))
LLM_CONTEXT_WINDOW_TOKENS = int(os.environ.get("LLM_CONTEXT_WINDOW_TOKENS", "0") or "0")
LLM_CONTEXT_TOKEN_RESERVE = int(os.environ.get("LLM_CONTEXT_TOKEN_RESERVE", "4096") or "4096")
DEEPSEEK_V4_PRO_CONTEXT_TOKENS = 131_072

# LiteLLM routes OpenAI-compatible calls through the OpenAI Python SDK, which
# sends User-Agent: OpenAI/Python and x-stainless-* telemetry. Many third-party
# gateways / Cloudflare fronts block that fingerprint ("Your request was blocked").
LLM_USER_AGENT = (
    os.environ.get("LITELLM_USER_AGENT")
    or os.environ.get("DEFECTMINE_LLM_USER_AGENT")
    or "DefectMine/1.0"
)


def litellm_extra_headers() -> dict[str, str]:
    return {"User-Agent": LLM_USER_AGENT}


def with_litellm_compat(kwargs: dict[str, Any]) -> dict[str, Any]:
    payload = dict(kwargs)
    headers = litellm_extra_headers()
    existing = payload.get("extra_headers")
    if isinstance(existing, dict):
        headers.update(existing)
    payload["extra_headers"] = headers
    return payload


def chat_with_llm(
    system_message: str,
    user_message: str,
    *,
    temperature: float = 0.1,
    max_tokens: int = 3500,
) -> str:
    response = chat_completion(
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    message = response_message_to_dict(response)
    content = message.get("content")
    return content or "No valid response content."


def _is_deepseek_llm(llm: dict[str, Any]) -> bool:
    blob = " ".join(
        str(llm.get(key) or "")
        for key in ("base_url", "model_name", "protocol")
    ).lower()
    return "deepseek" in blob


def _is_mimo_llm(llm: dict[str, Any]) -> bool:
    blob = " ".join(
        str(llm.get(key) or "")
        for key in ("base_url", "model_name", "protocol", "name")
    ).lower()
    return "mimo" in blob or "xiaomimimo" in blob


def _is_mini_custom_llm(llm: dict[str, Any]) -> bool:
    return str(llm.get("config_type") or "").strip() == CONFIG_TYPE_MINI_CUSTOM


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def build_litellm_extra_body(
    llm: dict[str, Any],
    *,
    thinking: bool | None = None,
) -> dict[str, Any] | None:
    if _is_mini_custom_llm(llm):
        config = llm.get("mini_config") if isinstance(llm.get("mini_config"), dict) else {}
        effective_thinking = (
            thinking
            if thinking is not None
            else _coerce_bool(config.get("thinking"), default=False)
        )
        chat_template_kwargs: dict[str, Any] = {"thinking": bool(effective_thinking)}
        if effective_thinking:
            effort = str(config.get("reasoning_effort") or "high").strip().lower()
            if effort in {"high", "max"}:
                chat_template_kwargs["reasoning_effort"] = effort

        extra_body: dict[str, Any] = {"chat_template_kwargs": chat_template_kwargs}
        for key in ("top_k", "min_p", "repetition_penalty"):
            if key in config and config[key] is not None:
                extra_body[key] = config[key]
        return extra_body

    if _is_deepseek_llm(llm):
        effective_thinking = bool(thinking) if thinking is not None else False
        return {"thinking": {"type": "enabled" if effective_thinking else "disabled"}}

    return None


def _context_window_tokens(llm: dict[str, Any]) -> int | None:
    if LLM_CONTEXT_WINDOW_TOKENS > 0:
        return LLM_CONTEXT_WINDOW_TOKENS
    blob = " ".join(
        str(llm.get(key) or "")
        for key in ("base_url", "model_name", "protocol", "config_type")
    ).lower()
    if "deepseek-v4-pro" in blob or "apiai.sztu.edu.cn" in blob:
        return DEEPSEEK_V4_PRO_CONTEXT_TOKENS
    return None


def _estimate_message_tokens(messages: list[dict[str, Any]]) -> int:
    total_chars = 0
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            total_chars += len(content)
        elif content is not None:
            total_chars += len(str(content))
        for key in ("tool_calls", "reasoning_content"):
            value = message.get(key)
            if value:
                total_chars += len(str(value))
    return (total_chars + 2) // 3 + (len(messages) * 8)


def _enforce_context_window(
    llm: dict[str, Any],
    messages: list[dict[str, Any]],
    *,
    max_tokens: int,
) -> None:
    window = _context_window_tokens(llm)
    if not window:
        return
    estimated_prompt_tokens = _estimate_message_tokens(messages)
    available_prompt_tokens = max(1, window - max_tokens - LLM_CONTEXT_TOKEN_RESERVE)
    if estimated_prompt_tokens <= available_prompt_tokens:
        return
    raise ValueError(
        "LLM input exceeds configured context budget before request is sent: "
        f"estimated_prompt_tokens={estimated_prompt_tokens}, "
        f"available_prompt_tokens={available_prompt_tokens}, "
        f"context_window_tokens={window}, max_tokens={max_tokens}. "
        "Reduce or compact the prompt payload."
    )


def _sanitize_messages(
    messages: list[dict[str, Any]],
    llm: dict[str, Any],
) -> list[dict[str, Any]]:
    """Drop provider-specific fields that break the selected OpenAI-compat API."""
    if _is_deepseek_llm(llm) and not _is_mini_custom_llm(llm):
        return [dict(message) for message in messages]
    cleaned: list[dict[str, Any]] = []
    for message in messages:
        item = dict(message)
        item.pop("reasoning_content", None)
        if _is_mini_custom_llm(llm) and item.get("role") == "tool":
            item.pop("name", None)
        cleaned.append(item)
    return cleaned


def _is_param_error(err: BaseException) -> bool:
    text = f"{type(err).__name__} {err}".lower()
    if (
        "badrequest" not in text
        and "invalid_request_error" not in text
        and "param incorrect" not in text
        and "invalid parameter" not in text
    ):
        return False
    # Only treat as param-shape error when the message points at request params.
    hints = (
        "param incorrect",
        "invalid parameter",
        "response_format",
        "json_object",
        "tool_choice",
        "tools",
    )
    return any(hint in text for hint in hints)


def chat_completion(
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None = None,
    tool_choice: str | dict[str, Any] | None = None,
    response_format: dict[str, Any] | None = None,
    temperature: float = 0.1,
    max_tokens: int = 3500,
    thinking: bool | None = None,
):
    llm = get_active_llm_config(require=True)
    assert llm is not None
    model = litellm_model_name(llm)
    base_url = llm["base_url"].rstrip("/")
    sanitized_messages = _sanitize_messages(messages, llm)
    _enforce_context_window(llm, sanitized_messages, max_tokens=max_tokens)
    if _is_mimo_llm(llm):
        return _mimo_chat_completion(
            llm,
            messages=sanitized_messages,
            tools=tools,
            tool_choice=tool_choice,
            response_format=response_format,
            temperature=temperature,
            max_tokens=max_tokens,
            thinking=thinking,
        )

    def _kwargs(
        *,
        include_tools: bool,
        include_response_format: bool,
        include_extra_body: bool,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "api_key": llm["api_key"],
            "api_base": base_url,
            "messages": sanitized_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": LLM_REQUEST_TIMEOUT_S,
        }
        if include_tools and tools is not None:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice or "auto"
        if include_response_format and response_format is not None:
            payload["response_format"] = response_format
        extra_body = build_litellm_extra_body(llm, thinking=thinking) if include_extra_body else None
        if extra_body:
            payload["extra_body"] = extra_body
        return payload

    # Default: send both `tools` and `response_format` per OpenAI spec. This is
    # required by the multi-turn audit/callscan loop, which relies on the model
    # eventually emitting a JSON object to break out of the tool loop.
    kwargs = _kwargs(include_tools=True, include_response_format=True, include_extra_body=True)

    log_request(
        model=model,
        messages=sanitized_messages,
        tools=tools,
        tool_choice=kwargs.get("tool_choice"),
        temperature=temperature,
        max_tokens=max_tokens,
    )
    try:
        response = completion(**with_litellm_compat(kwargs))
    except BaseException as err:
        if not _is_param_error(err):
            log_error(model=model, error=err)
            raise

        # Only retry on real "request shape" rejections. Drop response_format
        # first (most providers accept tools+json_object, a few don't), then
        # drop tools as a last resort.
        fallback_specs = []
        if kwargs.get("extra_body") is not None:
            fallback_specs.append(
                {
                    "include_tools": tools is not None,
                    "include_response_format": response_format is not None,
                    "include_extra_body": False,
                }
            )
        if response_format is not None:
            fallback_specs.append(
                {
                    "include_tools": tools is not None,
                    "include_response_format": False,
                    "include_extra_body": False,
                }
            )
        if tools is not None:
            fallback_specs.append(
                {
                    "include_tools": False,
                    "include_response_format": False,
                    "include_extra_body": False,
                }
            )
        last_err: BaseException = err
        for spec in fallback_specs:
            try:
                response = completion(**with_litellm_compat(_kwargs(**spec)))
            except BaseException as retry_err:  # noqa: PERF203
                last_err = retry_err
                continue
            log_response(model=model, response=response)
            return response
        log_error(model=model, error=last_err)
        raise last_err from err
    log_response(model=model, response=response)
    return response


def _mimo_chat_completion(
    llm: dict[str, Any],
    *,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
    tool_choice: str | dict[str, Any] | None,
    response_format: dict[str, Any] | None,
    temperature: float,
    max_tokens: int,
    thinking: bool | None,
) -> dict[str, Any]:
    model = _mimo_model_name(llm)
    base_url = _mimo_chat_url(str(llm.get("base_url") or ""))

    def payload(*, include_tools: bool, include_response_format: bool) -> dict[str, Any]:
        item: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            # MiMo OpenAI-compatible API expects max_completion_tokens.
            "max_completion_tokens": max_tokens,
            "stream": False,
            "thinking": {"type": "enabled" if _mimo_thinking_enabled(llm, thinking) else "disabled"},
        }
        if include_tools and tools is not None:
            item["tools"] = tools
            item["tool_choice"] = tool_choice or "auto"
        if include_response_format and response_format is not None:
            item["response_format"] = response_format
        return item

    log_request(
        model=f"mimo/{model}",
        messages=messages,
        tools=tools,
        tool_choice=tool_choice or ("auto" if tools else None),
        temperature=temperature,
        max_tokens=max_tokens,
    )
    specs = [
        {"include_tools": tools is not None, "include_response_format": response_format is not None},
        {"include_tools": tools is not None, "include_response_format": False},
        {"include_tools": False, "include_response_format": False},
    ]
    last_err: BaseException | None = None
    for spec in specs:
        try:
            response = _post_mimo_chat(base_url, str(llm.get("api_key") or ""), payload(**spec))
        except BaseException as err:  # noqa: PERF203
            last_err = err
            if not _is_param_error(err):
                log_error(model=f"mimo/{model}", error=err)
                raise
            continue
        log_response(model=f"mimo/{model}", response=response)
        return response
    assert last_err is not None
    log_error(model=f"mimo/{model}", error=last_err)
    raise last_err


def _post_mimo_chat(url: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "api-key": api_key,
            "User-Agent": LLM_USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=LLM_REQUEST_TIMEOUT_S) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"MiMo HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"MiMo request failed: {exc}") from exc
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError("MiMo response is not a JSON object")
    return parsed


def _mimo_chat_url(base_url: str) -> str:
    url = base_url.strip().rstrip("/")
    if url.endswith("/chat/completions"):
        return url
    if url.endswith("/v1"):
        return f"{url}/chat/completions"
    return f"{url}/v1/chat/completions"


def _mimo_model_name(llm: dict[str, Any]) -> str:
    model = str(llm.get("model_name") or "").strip()
    model = model.split("/", 1)[1] if "/" in model else model
    # MiMo's OpenAI-compatible endpoint treats model ids as case-sensitive.
    # Normalize the known `mimo-*` family so UI input such as `mimo-V2.5-pro`
    # is sent as the supported lowercase model id.
    return model.lower() if model.lower().startswith("mimo-") else model


def _mimo_thinking_enabled(llm: dict[str, Any], override: bool | None) -> bool:
    if override is not None:
        return bool(override)
    config = llm.get("mini_config") if isinstance(llm.get("mini_config"), dict) else {}
    return _coerce_bool(config.get("thinking"), default=False)


def response_message_to_dict(response) -> dict[str, Any]:
    if isinstance(response, dict):
        choices = response.get("choices")
        if isinstance(choices, list) and choices:
            choice = choices[0]
            if isinstance(choice, dict):
                message = choice.get("message")
                if isinstance(message, dict):
                    return dict(message)
        return {}
    message = response.choices[0].message
    if hasattr(message, "model_dump"):
        data = message.model_dump(exclude_none=True)
    elif isinstance(message, dict):
        data = dict(message)
    else:
        data = {
            "role": getattr(message, "role", "assistant"),
            "content": getattr(message, "content", None),
        }
        tool_calls = getattr(message, "tool_calls", None)
        if tool_calls is not None:
            data["tool_calls"] = [
                item.model_dump(exclude_none=True) if hasattr(item, "model_dump") else item
                for item in tool_calls
            ]

    if "reasoning_content" not in data:
        reasoning = getattr(message, "reasoning_content", None)
        if reasoning is None:
            provider_specific = getattr(message, "provider_specific_fields", None) or {}
            if isinstance(provider_specific, dict):
                reasoning = provider_specific.get("reasoning_content")
        if reasoning:
            data["reasoning_content"] = reasoning
    return data

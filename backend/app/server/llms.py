"""LLM settings API helpers."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from time import perf_counter
from typing import Any

from litellm import completion

from app.llm.client import (
    _is_mimo_llm,
    _is_param_error,
    _mimo_chat_completion,
    build_litellm_extra_body,
    response_message_to_dict,
    with_litellm_compat,
)
from app.core.llm_settings import (
    create_profile,
    delete_profile,
    list_public_settings,
    litellm_model_name,
    profile_from_test_payload,
    select_profile,
    update_profile,
)

MAX_CONCURRENT_LLM_TESTS = 50


def list_llms() -> dict[str, Any]:
    return list_public_settings()


def create_llm(payload: dict[str, Any]) -> dict[str, Any]:
    return create_profile(payload)


def update_llm(llm_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return update_profile(llm_id, payload)


def delete_llm(llm_id: str) -> dict[str, Any]:
    return delete_profile(llm_id)


def select_llm(llm_id: str) -> dict[str, Any]:
    return select_profile(llm_id)


def test_llm(payload: dict[str, Any]) -> dict[str, Any]:
    profile = profile_from_test_payload(payload)
    return _test_profile(profile)


def run_llm_concurrent_test(payload: dict[str, Any]) -> dict[str, Any]:
    profile = profile_from_test_payload(payload)
    count = _bounded_int(
        payload.get("count", payload.get("concurrency", 5)),
        default=5,
        minimum=1,
        maximum=MAX_CONCURRENT_LLM_TESTS,
        field="count",
    )
    success_threshold = _bounded_int(
        payload.get("success_threshold", count),
        default=count,
        minimum=1,
        maximum=count,
        field="success_threshold",
    )

    started = perf_counter()
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = {
            executor.submit(_test_profile, profile): index
            for index in range(1, count + 1)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                results.append(
                    {
                        "index": index,
                        "ok": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            else:
                results.append(
                    {
                        "index": index,
                        "ok": True,
                        "latency_ms": result.get("latency_ms", 0),
                        "message": result.get("message", ""),
                    }
                )

    results.sort(key=lambda item: int(item.get("index") or 0))
    success_count = sum(1 for item in results if item.get("ok"))
    elapsed_ms = int((perf_counter() - started) * 1000)
    model = litellm_model_name(profile)
    base_url = str(profile.get("base_url") or "").rstrip("/")
    return {
        "ok": success_count >= success_threshold,
        "model": model,
        "base_url": base_url,
        "total": count,
        "success_threshold": success_threshold,
        "success_count": success_count,
        "failure_count": count - success_count,
        "latency_ms": elapsed_ms,
        "results": results,
    }


def _test_profile(profile: dict[str, Any]) -> dict[str, Any]:
    model = litellm_model_name(profile)
    base_url = str(profile.get("base_url") or "").rstrip("/")
    if _is_mimo_llm(profile):
        started = perf_counter()
        response = _mimo_chat_completion(
            profile,
            messages=[
                {
                    "role": "user",
                    "content": "Reply with exactly: ok",
                }
            ],
            tools=None,
            tool_choice=None,
            response_format=None,
            temperature=0,
            max_tokens=64,
            thinking=False,
        )
        elapsed_ms = int((perf_counter() - started) * 1000)
        message = response_message_to_dict(response)
        return {
            "ok": True,
            "model": model,
            "base_url": base_url,
            "latency_ms": elapsed_ms,
            "message": message.get("content") or "",
        }

    kwargs: dict[str, Any] = {
        "model": model,
        "api_key": str(profile.get("api_key") or ""),
        "api_base": base_url,
        "messages": [
            {
                "role": "user",
                "content": "Reply with exactly: ok",
            }
        ],
        "temperature": 0,
        "max_tokens": 64,
    }
    extra_body = build_litellm_extra_body(profile)
    if extra_body:
        kwargs["extra_body"] = extra_body

    started = perf_counter()
    try:
        response = completion(**with_litellm_compat(kwargs))
    except BaseException as err:
        # Some OpenAI-compatible gateways reject provider-specific Mini params
        # such as chat_template_kwargs/top_k/min_p. Keep the profile usable by
        # retrying the minimal request shape before surfacing the error.
        if "extra_body" not in kwargs or not _is_param_error(err):
            raise
        retry_kwargs = dict(kwargs)
        retry_kwargs.pop("extra_body", None)
        response = completion(**with_litellm_compat(retry_kwargs))
    elapsed_ms = int((perf_counter() - started) * 1000)
    message = response_message_to_dict(response)
    content = message.get("content")
    return {
        "ok": True,
        "model": model,
        "base_url": base_url,
        "latency_ms": elapsed_ms,
        "message": content or "",
    }


def _bounded_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
    field: str,
) -> int:
    if value in (None, ""):
        parsed = default
    else:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}")
    return parsed

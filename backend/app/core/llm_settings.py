"""Persistent LLM profile settings.

The legacy configuration lives in ``backend/app/config/.env`` and is exposed
through ``app.core.config``.  This module adds a JSON-backed profile store so
the running app can switch the active LLM without restarting.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import dotenv_values


CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
ENV_PATH = CONFIG_DIR / ".env"
STORE_PATH = CONFIG_DIR / "llms.json"

ENV_KEYS = {
    "base_url": "LLM_BASEURL",
    "api_key": "LLM_APIKEY",
    "model_name": "LLM_MODEL",
    "protocol": "LLM_PROVIDER",
}

CONFIG_TYPE_STANDARD = "standard"
CONFIG_TYPE_MINI_CUSTOM = "mini_custom"
MINI_CONFIG_DEFAULTS: dict[str, Any] = {
    "thinking": False,
    "reasoning_effort": "high",
    "top_k": -1,
    "min_p": 0.0,
    "repetition_penalty": 1.0,
}


def read_env_config() -> dict[str, Any]:
    """Read the config that ``app.core.config`` historically exposes."""
    values: dict[str, str] = {}
    if ENV_PATH.is_file():
        parsed = dotenv_values(ENV_PATH)
        values = {
            key: str(parsed.get(env_key) or os.getenv(env_key) or "").strip()
            for key, env_key in ENV_KEYS.items()
        }

    return {
        "path": str(ENV_PATH),
        "exists": ENV_PATH.is_file(),
        "base_url": values.get("base_url", ""),
        "model_name": values.get("model_name", ""),
        "protocol": values.get("protocol", ""),
        "has_api_key": bool(values.get("api_key")),
        "api_key_masked": mask_secret(values.get("api_key", "")),
        "complete": _is_complete(values),
    }


def list_public_settings() -> dict[str, Any]:
    store = _load_store(init_from_env=True)
    active_id = store.get("active_id")
    items = [
        _public_profile(profile, active=profile.get("id") == active_id)
        for profile in store.get("items", [])
    ]
    return {
        "active_id": active_id,
        "items": items,
        "file_config": read_env_config(),
        "store_path": str(STORE_PATH),
    }


def create_profile(payload: dict[str, Any]) -> dict[str, Any]:
    profile = _profile_from_payload(payload)
    profile["id"] = uuid.uuid4().hex
    now = _now_iso()
    profile["created_at"] = now
    profile["updated_at"] = now

    store = _load_store(init_from_env=True)
    store.setdefault("items", []).append(profile)
    became_active = not store.get("active_id")
    if not store.get("active_id"):
        store["active_id"] = profile["id"]
    _write_store(store)
    if became_active:
        sync_profile_to_env(profile)
    return _public_profile(profile, active=profile["id"] == store.get("active_id"))


def update_profile(profile_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    store = _load_store(init_from_env=True)
    items = list(store.get("items", []))
    for index, current in enumerate(items):
        if current.get("id") != profile_id:
            continue
        updated = _profile_from_payload(payload, current=current)
        updated["id"] = current["id"]
        updated["created_at"] = current.get("created_at") or _now_iso()
        updated["updated_at"] = _now_iso()
        items[index] = updated
        store["items"] = items
        _write_store(store)
        if store.get("active_id") == profile_id:
            sync_profile_to_env(updated)
        return _public_profile(updated, active=store.get("active_id") == profile_id)
    raise FileNotFoundError(f"LLM profile not found: {profile_id}")


def delete_profile(profile_id: str) -> dict[str, Any]:
    store = _load_store(init_from_env=True)
    items = list(store.get("items", []))
    next_items = [item for item in items if item.get("id") != profile_id]
    if len(next_items) == len(items):
        raise FileNotFoundError(f"LLM profile not found: {profile_id}")

    was_active = store.get("active_id") == profile_id
    if store.get("active_id") == profile_id:
        store["active_id"] = next_items[0]["id"] if next_items else None
    store["items"] = next_items
    _write_store(store)
    if was_active:
        if next_items:
            sync_profile_to_env(next_items[0])
        else:
            clear_env_config()
    return list_public_settings()


def select_profile(profile_id: str) -> dict[str, Any]:
    store = _load_store(init_from_env=True)
    profile = _find_profile(store, profile_id)
    store["active_id"] = profile["id"]
    _write_store(store)
    sync_profile_to_env(profile)
    return _public_profile(profile, active=True)


def get_profile(profile_id: str) -> dict[str, Any]:
    store = _load_store(init_from_env=True)
    return dict(_find_profile(store, profile_id))


def get_active_llm_config(*, require: bool = False) -> dict[str, Any] | None:
    """Return the runtime LLM config used by scan agents.

    When ``llms.json`` exists, the active profile in the store is the source of
    truth (same as the settings-page test endpoint).  ``.env`` is only used when
    there is no usable store profile, so a stale ``.env`` cannot override the
    profile the user selected in the UI.
    """
    store_exists = STORE_PATH.is_file()
    store = _load_store(init_from_env=not store_exists)
    profile = _resolve_active_store_profile(store)
    if profile is not None:
        if not _env_matches_profile(profile):
            sync_profile_to_env(profile)
        return _runtime_config_from_profile(profile)

    env_profile = _env_profile()
    if env_profile is not None:
        return _runtime_config_from_profile(env_profile)

    if require:
        raise ValueError(
            "No LLM profile configured. Add one in LLM settings or provide backend/app/config/.env."
        )
    return None


def profile_from_test_payload(payload: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(payload.get("llm_id") or "").strip()
    if profile_id:
        profile = get_profile(profile_id)
        override_keys = {
            "name",
            "notes",
            "base_url",
            "baseurl",
            "api_key",
            "model_name",
            "model",
            "protocol",
            "provider",
            "config_type",
            "mini_config",
        }
        if any(key in payload for key in override_keys):
            tested = _profile_from_payload(payload, current=profile)
            tested["id"] = profile["id"]
            tested["created_at"] = profile.get("created_at")
            tested["updated_at"] = profile.get("updated_at")
            return tested
        return profile
    return _profile_from_payload(payload)


def litellm_model_name(profile: dict[str, Any]) -> str:
    protocol = str(profile.get("protocol") or "").strip()
    model_name = str(profile.get("model_name") or "").strip()
    return f"{protocol}/{model_name}" if protocol else model_name


def mask_secret(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:3]}{'*' * 6}{text[-4:]}"


def sync_profile_to_env(profile: dict[str, Any]) -> None:
    _write_env_values(
        {
            ENV_KEYS["base_url"]: str(profile.get("base_url") or "").strip(),
            ENV_KEYS["api_key"]: str(profile.get("api_key") or "").strip(),
            ENV_KEYS["model_name"]: str(profile.get("model_name") or "").strip(),
            ENV_KEYS["protocol"]: str(profile.get("protocol") or "").strip(),
        }
    )


def clear_env_config() -> None:
    _write_env_values({env_key: "" for env_key in ENV_KEYS.values()})


def _profile_from_payload(
    payload: dict[str, Any],
    *,
    current: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current = current or {}
    profile = {
        "name": str(payload.get("name") or current.get("name") or "").strip(),
        "notes": str(payload.get("notes", current.get("notes") or "") or "").strip(),
        "base_url": str(
            payload.get("base_url")
            or payload.get("baseurl")
            or current.get("base_url")
            or ""
        ).strip(),
        "api_key": str(payload.get("api_key") or current.get("api_key") or "").strip(),
        "model_name": str(
            payload.get("model_name")
            or payload.get("model")
            or current.get("model_name")
            or ""
        ).strip(),
        "protocol": str(
            payload.get("protocol")
            or payload.get("provider")
            or current.get("protocol")
            or ""
        ).strip(),
    }
    profile["model_name"] = _normalize_model_name(profile)
    profile["config_type"] = _normalize_config_type(
        payload.get("config_type", current.get("config_type", CONFIG_TYPE_STANDARD))
    )
    profile["mini_config"] = _mini_config_from_payload(
        payload.get("mini_config"),
        current=current.get("mini_config") if isinstance(current, dict) else None,
    )
    missing = [
        label
        for label, value in {
            "name": profile["name"],
            "base_url": profile["base_url"],
            "api_key": profile["api_key"],
            "model_name": profile["model_name"],
            "protocol": profile["protocol"],
        }.items()
        if not value
    ]
    if missing:
        raise ValueError(f"Missing required LLM profile fields: {', '.join(missing)}")
    return profile


def _normalize_model_name(profile: dict[str, Any]) -> str:
    """Normalize provider-specific model ids before saving or testing."""
    model = str(profile.get("model_name") or "").strip()
    blob = " ".join(
        str(profile.get(key) or "")
        for key in ("name", "base_url", "protocol", "model_name")
    ).lower()
    if ("mimo" in blob or "xiaomimimo" in blob) and model.lower().startswith("mimo-"):
        return model.lower()
    return model


def _runtime_config_from_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "base_url": str(profile.get("base_url") or "").strip(),
        "api_key": str(profile.get("api_key") or "").strip(),
        "model_name": str(profile.get("model_name") or "").strip(),
        "protocol": str(profile.get("protocol") or "").strip(),
        "name": str(profile.get("name") or "").strip(),
        "id": str(profile.get("id") or "").strip(),
        "config_type": _normalize_config_type(profile.get("config_type")),
        "mini_config": _mini_config_from_payload(profile.get("mini_config")),
    }


def _write_env_values(values: dict[str, str]) -> None:
    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if ENV_PATH.is_file():
        text = ENV_PATH.read_text(encoding="utf-8-sig")
        lines = text.splitlines()

    seen: set[str] = set()
    next_lines: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            next_lines.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in values:
            next_lines.append(f"{key}={_format_env_value(values[key])}")
            seen.add(key)
        else:
            next_lines.append(line)

    missing_keys = [env_key for env_key in ENV_KEYS.values() if env_key in values and env_key not in seen]
    if missing_keys and next_lines and next_lines[-1].strip():
        next_lines.append("")
    for key in missing_keys:
        next_lines.append(f"{key}={_format_env_value(values[key])}")

    ENV_PATH.write_text("\n".join(next_lines).rstrip() + "\n", encoding="utf-8")


def _format_env_value(value: str) -> str:
    return json.dumps(str(value or ""), ensure_ascii=False)


def _load_store(*, init_from_env: bool) -> dict[str, Any]:
    store_missing = not STORE_PATH.is_file()
    store = _read_store()
    if init_from_env and store_missing and not store.get("items"):
        env_profile = _env_profile()
        if env_profile:
            store = {"active_id": env_profile["id"], "items": [env_profile]}
            _write_store(store)

    items = [_normalize_stored_profile(item) for item in store.get("items", [])]
    active_id = str(store.get("active_id") or "").strip() or None
    if active_id and not any(item.get("id") == active_id for item in items):
        active_id = None
    if not active_id and items:
        active_id = items[0]["id"]
    return {"active_id": active_id, "items": items}


def _read_store() -> dict[str, Any]:
    if not STORE_PATH.is_file():
        return {"active_id": None, "items": []}
    try:
        data = json.loads(STORE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"active_id": None, "items": []}
    if not isinstance(data, dict):
        return {"active_id": None, "items": []}
    items = data.get("items")
    if not isinstance(items, list):
        items = []
    return {"active_id": data.get("active_id"), "items": items}


def _write_store(store: dict[str, Any]) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "active_id": store.get("active_id"),
        "items": store.get("items", []),
    }
    STORE_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _env_profile() -> dict[str, Any] | None:
    if not ENV_PATH.is_file():
        return None
    parsed = dotenv_values(ENV_PATH)
    values = {
        key: str(parsed.get(env_key) or os.getenv(env_key) or "").strip()
        for key, env_key in ENV_KEYS.items()
    }
    if not _is_complete(values):
        return None
    now = _now_iso()
    return {
        "id": "env-default",
        "name": "config.py/.env",
        "notes": "Imported from backend/app/config/.env",
        "base_url": values["base_url"],
        "api_key": values["api_key"],
        "model_name": values["model_name"],
        "protocol": values["protocol"],
        "config_type": CONFIG_TYPE_STANDARD,
        "mini_config": dict(MINI_CONFIG_DEFAULTS),
        "created_at": now,
        "updated_at": now,
    }


def _normalize_stored_profile(profile: Any) -> dict[str, Any]:
    if not isinstance(profile, dict):
        profile = {}
    now = _now_iso()
    return {
        "id": str(profile.get("id") or uuid.uuid4().hex).strip(),
        "name": str(profile.get("name") or "Unnamed LLM").strip(),
        "notes": str(profile.get("notes") or "").strip(),
        "base_url": str(profile.get("base_url") or profile.get("baseurl") or "").strip(),
        "api_key": str(profile.get("api_key") or "").strip(),
        "model_name": str(profile.get("model_name") or profile.get("model") or "").strip(),
        "protocol": str(profile.get("protocol") or profile.get("provider") or "").strip(),
        "config_type": _normalize_config_type(profile.get("config_type")),
        "mini_config": _mini_config_from_payload(profile.get("mini_config")),
        "created_at": profile.get("created_at") or now,
        "updated_at": profile.get("updated_at") or now,
    }


def _public_profile(profile: dict[str, Any], *, active: bool) -> dict[str, Any]:
    return {
        "id": profile.get("id"),
        "name": profile.get("name") or "",
        "notes": profile.get("notes") or "",
        "base_url": profile.get("base_url") or "",
        "model_name": profile.get("model_name") or "",
        "protocol": profile.get("protocol") or "",
        "config_type": _normalize_config_type(profile.get("config_type")),
        "mini_config": _mini_config_from_payload(profile.get("mini_config")),
        "has_api_key": bool(profile.get("api_key")),
        "api_key_masked": mask_secret(str(profile.get("api_key") or "")),
        "active": active,
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
    }


def _find_profile(store: dict[str, Any], profile_id: str) -> dict[str, Any]:
    for profile in store.get("items", []):
        if profile.get("id") == profile_id:
            return profile
    raise FileNotFoundError(f"LLM profile not found: {profile_id}")


def _resolve_active_store_profile(store: dict[str, Any]) -> dict[str, Any] | None:
    items = store.get("items") or []
    if not items:
        return None

    active_id = store.get("active_id")
    profile: dict[str, Any] | None = None
    if active_id:
        try:
            profile = _find_profile(store, active_id)
        except FileNotFoundError:
            profile = None
    if profile is None:
        profile = items[0]

    values = {
        "base_url": profile.get("base_url"),
        "api_key": profile.get("api_key"),
        "model_name": profile.get("model_name"),
        "protocol": profile.get("protocol"),
    }
    if not _is_complete(values):
        return None
    return profile


def _is_complete(values: dict[str, Any]) -> bool:
    return all(str(values.get(key) or "").strip() for key in ENV_KEYS)


def _normalize_config_type(value: Any) -> str:
    text = str(value or "").strip()
    if text == CONFIG_TYPE_MINI_CUSTOM:
        return CONFIG_TYPE_MINI_CUSTOM
    return CONFIG_TYPE_STANDARD


def _mini_config_from_payload(
    payload: Any,
    *,
    current: Any | None = None,
) -> dict[str, Any]:
    source = payload if isinstance(payload, dict) else {}
    fallback = current if isinstance(current, dict) else MINI_CONFIG_DEFAULTS
    config = {
        "thinking": _coerce_bool(
            source.get("thinking", fallback.get("thinking", MINI_CONFIG_DEFAULTS["thinking"])),
            default=MINI_CONFIG_DEFAULTS["thinking"],
        ),
        "reasoning_effort": _normalize_reasoning_effort(
            source.get(
                "reasoning_effort",
                fallback.get("reasoning_effort", MINI_CONFIG_DEFAULTS["reasoning_effort"]),
            )
        ),
        "top_k": _coerce_int(
            source.get("top_k", fallback.get("top_k", MINI_CONFIG_DEFAULTS["top_k"])),
            field="top_k",
        ),
        "min_p": _coerce_float(
            source.get("min_p", fallback.get("min_p", MINI_CONFIG_DEFAULTS["min_p"])),
            field="min_p",
        ),
        "repetition_penalty": _coerce_float(
            source.get(
                "repetition_penalty",
                fallback.get(
                    "repetition_penalty",
                    MINI_CONFIG_DEFAULTS["repetition_penalty"],
                ),
            ),
            field="repetition_penalty",
        ),
    }
    if config["top_k"] < -1:
        raise ValueError("top_k must be -1 or greater")
    if config["min_p"] < 0:
        raise ValueError("min_p must be greater than or equal to 0")
    if config["repetition_penalty"] <= 0:
        raise ValueError("repetition_penalty must be greater than 0")
    return config


def _normalize_reasoning_effort(value: Any) -> str:
    text = str(value or MINI_CONFIG_DEFAULTS["reasoning_effort"]).strip().lower()
    if text in {"high", "max"}:
        return text
    raise ValueError("reasoning_effort must be 'high' or 'max'")


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


def _coerce_int(value: Any, *, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc


def _coerce_float(value: Any, *, field: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a number") from exc


def _env_matches_profile(profile: dict[str, Any]) -> bool:
    env_profile = _env_profile()
    if env_profile is None:
        return False
    for key in ENV_KEYS:
        if str(env_profile.get(key) or "").strip() != str(profile.get(key) or "").strip():
            return False
    return True


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")

"""Compatibility module for LLM configuration constants."""

from __future__ import annotations

from pathlib import Path

from app.core.llm_settings import ENV_PATH as CONFIG_ENV_PATH, get_active_llm_config


cfg = get_active_llm_config(require=True)

LLM_BASEURL = cfg["base_url"]
LLM_APIKEY = cfg["api_key"]
LLM_MODEL = cfg["model_name"]
LLM_PROVIDER = cfg["protocol"]

# Keep the old public name for callers that inspect the config module.
ENV_PATH: Path = CONFIG_ENV_PATH

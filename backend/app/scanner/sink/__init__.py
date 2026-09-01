"""Sink rule registry.

Rules live under `app.scanner.sink.<language>.<vulnerability_type>` modules.
Each module exposes a module-level `RULES: list[SinkRule]`.

Public API（保持与旧 sink.py 完全兼容）:
- SinkRule
- SEVERITY_RANK
- iter_sink_rules(language)
- iter_all_sink_rules()
- line_is_dynamic(line)
- matches_extra(rule, line)
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from typing import Iterable

from .types import (
    SEVERITY_RANK,
    SinkRule,
    line_is_dynamic,
    matches_extra,
)

# 已知支持的语言子包（与上层 detect-language 逻辑对齐）
LANGUAGES: tuple[str, ...] = (
    "php",
    "python",
    "javascript",
    "typescript",
    "java",
    "go",
    "rust",
    "c",
    "cpp",
    "html",
)

# 漏洞类型标签 → 优先级（排序展示用，无碰撞需求）
VULNERABILITY_TYPES: tuple[str, ...] = (
    "sql_injection",
    "nosql_injection",
    "graphql_injection",
    "xss",
    "file_upload",
    "file_inclusion",
    "file_download",
    "file_path",
    "command_execution",
    "code_execution",
    "path_traversal",
    "deserialization",
    "ssrf",
    "csrf",
    "xxe",
    "xpath_injection",
    "ldap_injection",
    "crlf_injection",
    "ssti",
    "auth_bypass",
    "unauthorized_access",
    "info_disclosure",
    "weak_credential",
    "buffer_overflow",
)


_RULES_CACHE: dict[str, list[tuple[str, SinkRule]]] | None = None


def _load_rules() -> dict[str, list[tuple[str, SinkRule]]]:
    """Lazy-load every `app.scanner.sink.<lang>.<vuln>` module's RULES.

    返回 {language: [(vulnerability_type, rule), ...]}。
    """
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE

    bucket: dict[str, list[tuple[str, SinkRule]]] = {lang: [] for lang in LANGUAGES}

    for lang in LANGUAGES:
        try:
            language_pkg = importlib.import_module(f"{__name__}.{lang}")
        except ModuleNotFoundError:
            continue
        for module_info in pkgutil.iter_modules(language_pkg.__path__):
            if module_info.name.startswith("_"):
                continue
            module = importlib.import_module(
                f"{__name__}.{lang}.{module_info.name}"
            )
            rules = getattr(module, "RULES", None)
            if not rules:
                continue
            vuln = getattr(module, "VULNERABILITY", module_info.name)
            for rule in rules:
                bucket[lang].append((vuln, rule))

    _RULES_CACHE = bucket
    return bucket


def iter_sink_rules(language: str) -> Iterable[tuple[str, SinkRule]]:
    """Iterate (vulnerability_type, rule) for one language."""
    return iter(_load_rules().get(language, []))


def iter_all_sink_rules() -> Iterable[tuple[str, str, SinkRule]]:
    """Iterate (language, vulnerability_type, rule) across every loaded rule."""
    for language, items in _load_rules().items():
        for vuln, rule in items:
            yield language, vuln, rule


def supported_languages() -> list[str]:
    return [lang for lang, items in _load_rules().items() if items]


__all__ = [
    "SinkRule",
    "SEVERITY_RANK",
    "VULNERABILITY_TYPES",
    "LANGUAGES",
    "iter_sink_rules",
    "iter_all_sink_rules",
    "supported_languages",
    "line_is_dynamic",
    "matches_extra",
]

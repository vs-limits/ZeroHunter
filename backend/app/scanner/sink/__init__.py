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
from dataclasses import dataclass
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


_CATEGORY_BY_VULNERABILITY = {
    "auth_bypass": "auth",
    "buffer_overflow": "memory-unsafe",
    "code_execution": "code-execution",
    "command_execution": "command-execution",
    "crlf_injection": "header-injection",
    "csrf": "csrf-risk",
    "deserialization": "deserialization",
    "file_download": "file-read-write",
    "file_inclusion": "file-read-write",
    "file_path": "file-read-write",
    "file_upload": "file-upload",
    "graphql_injection": "graphql-query",
    "info_disclosure": "info-disclosure",
    "ldap_injection": "ldap-query",
    "nosql_injection": "nosql-query",
    "path_traversal": "file-read-write",
    "sql_injection": "sql-query",
    "ssrf": "http-client",
    "ssti": "template-render",
    "unauthorized_access": "auth",
    "weak_credential": "weak-credential",
    "xpath_injection": "xpath-query",
    "xss": "xss",
    "xxe": "xml-parser",
}


_LANGUAGE_ALIASES = {
    "c": "c",
    "c++": "cpp",
    "cc": "cpp",
    "cpp": "cpp",
    "cxx": "cpp",
    "go": "go",
    "golang": "go",
    "html": "html",
    "java": "java",
    "javascript": "javascript",
    "js": "javascript",
    "node": "javascript",
    "nodejs": "javascript",
    "php": "php",
    "python": "python",
    "py": "python",
    "rust": "rust",
    "rs": "rust",
    "typescript": "typescript",
    "ts": "typescript",
}


@dataclass(frozen=True, slots=True)
class LoadedSinkRule:
    """CallScan-facing view over the modular sink rule library."""

    language: str
    vulnerability: str
    category: str
    rule: SinkRule

    @property
    def id(self) -> str:
        return self.rule.id

    @property
    def name(self) -> str:
        return self.rule.function

    @property
    def function(self) -> str:
        return self.rule.function

    @property
    def patterns(self) -> tuple[str, ...]:
        return (self.rule.call_regex,)

    @property
    def call_regex(self) -> str:
        return self.rule.call_regex

    @property
    def description(self) -> str:
        return self.rule.description

    @property
    def argument_roles(self) -> list[str]:
        return self.rule.argument_roles

    @property
    def extensions(self) -> list[str]:
        return self.rule.extensions

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def require_dynamic(self) -> bool:
        return self.rule.require_dynamic

    @property
    def extra_match_regex(self) -> list[str]:
        return self.rule.extra_match_regex

    def as_dict(self) -> dict:
        data = self.rule.to_dict()
        data.update(
            {
                "language": self.language,
                "vulnerability": self.vulnerability,
                "category": self.category,
                "patterns": [self.rule.call_regex],
            }
        )
        return data


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


def load_sink_rules(
    languages: Iterable[str] | None = None,
    categories: Iterable[str] | None = None,
    vulnerabilities: Iterable[str] | None = None,
) -> list[LoadedSinkRule]:
    """Compatibility API for CallScan over the modular sink registry."""
    normalized_languages = _normalize_languages(languages)
    normalized_categories = _normalize_values(categories)
    normalized_vulnerabilities = _normalize_vulnerabilities(vulnerabilities)

    rules: list[LoadedSinkRule] = []
    for language, vulnerability, rule in iter_all_sink_rules():
        category = _CATEGORY_BY_VULNERABILITY.get(vulnerability, vulnerability.replace("_", "-"))
        if normalized_languages and language not in normalized_languages:
            continue
        if normalized_categories and category not in normalized_categories and vulnerability not in normalized_categories:
            continue
        if normalized_vulnerabilities and vulnerability not in normalized_vulnerabilities:
            continue
        rules.append(
            LoadedSinkRule(
                language=language,
                vulnerability=vulnerability,
                category=category,
                rule=rule,
            )
        )
    return rules


def rules_as_dicts(rules: Iterable[LoadedSinkRule]) -> list[dict]:
    return [rule.as_dict() for rule in rules]


def coverage_as_dict() -> dict[str, dict[str, object]]:
    coverage: dict[str, dict[str, object]] = {}
    for language, vulnerability, _rule in iter_all_sink_rules():
        item = coverage.setdefault(language, {"rules": 0, "vuln_types": set(), "categories": set()})
        item["rules"] = int(item["rules"]) + 1
        item["vuln_types"].add(vulnerability)  # type: ignore[union-attr]
        item["categories"].add(_CATEGORY_BY_VULNERABILITY.get(vulnerability, vulnerability.replace("_", "-")))  # type: ignore[union-attr]
    return {
        language: {
            "rules": item["rules"],
            "vuln_types": sorted(item["vuln_types"]),  # type: ignore[arg-type]
            "categories": sorted(item["categories"]),  # type: ignore[arg-type]
        }
        for language, item in sorted(coverage.items())
    }


def rg_pattern_for_rules(rules: Iterable[LoadedSinkRule]) -> str:
    patterns = []
    for rule in rules:
        patterns.extend(rule.patterns)
    return "|".join(f"(?:{pattern})" for pattern in _unique(patterns))


def _normalize_languages(languages: Iterable[str] | None) -> set[str]:
    if languages is None:
        return set()
    normalized: set[str] = set()
    for language in languages:
        mapped = _LANGUAGE_ALIASES.get(str(language).strip().casefold())
        if mapped:
            normalized.add(mapped)
    return normalized


def _normalize_values(values: Iterable[str] | None) -> set[str]:
    if values is None:
        return set()
    return {str(value).strip().casefold().replace("_", "-") for value in values if str(value).strip()}


def _normalize_vulnerabilities(values: Iterable[str] | None) -> set[str]:
    if values is None:
        return set()
    return {str(value).strip().casefold().replace("-", "_") for value in values if str(value).strip()}


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        re.compile(normalized)
        seen.add(normalized)
        unique_values.append(normalized)
    return unique_values


__all__ = [
    "SinkRule",
    "LoadedSinkRule",
    "SEVERITY_RANK",
    "VULNERABILITY_TYPES",
    "LANGUAGES",
    "load_sink_rules",
    "rules_as_dicts",
    "coverage_as_dict",
    "rg_pattern_for_rules",
    "iter_sink_rules",
    "iter_all_sink_rules",
    "supported_languages",
    "line_is_dynamic",
    "matches_extra",
]

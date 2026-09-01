"""Semantic sink profile enrichment.

This layer does not encode CVEs or project-specific issues. It upgrades generic
dangerous-function hits with framework and vulnerability-shape metadata so later
agents know what evidence to repair.
"""

from __future__ import annotations

import re
from typing import Any


BREAKPOINT_EVIDENCE = {
    "source_control",
    "storage_identity",
    "storage_read",
    "template_binding",
    "sanitizer_state",
    "permission_check",
    "reachability",
    "file_save_path",
}


def enrich_sink_profile(
    sink_rule: dict[str, Any],
    *,
    language: str,
    vulnerability_type: str,
    file: str,
    code: str = "",
    function: str = "",
) -> dict[str, Any]:
    """Return a copy of sink_rule with L0/L1/L2 semantic metadata merged."""
    out = dict(sink_rule or {})
    out["level"] = _normalize_level(out.get("level"))
    out["semantic_tags"] = _dedupe(out.get("semantic_tags") or [])
    out["required_evidence"] = _dedupe(out.get("required_evidence") or [])
    out["repair_hints"] = _dedupe(out.get("repair_hints") or [])

    context = " ".join(
        str(part or "")
        for part in (language, vulnerability_type, file, code, function, out.get("id"), out.get("function"))
    )
    lower = context.lower()

    _apply_l0_defaults(out, vulnerability_type, lower)
    _apply_l1_framework_profile(out, language.lower(), lower)
    _apply_l2_shape_profile(out, vulnerability_type, lower)
    out["semantic_tags"] = _dedupe(out["semantic_tags"])
    out["required_evidence"] = _dedupe(out["required_evidence"])
    out["repair_hints"] = _dedupe(out["repair_hints"])
    return out


def _apply_l0_defaults(rule: dict[str, Any], vulnerability_type: str, lower: str) -> None:
    tags = rule["semantic_tags"]
    required = rule["required_evidence"]
    hints = rule["repair_hints"]

    tags.append("generic_sink")
    required.extend(["source_control", "sanitizer_state"])
    if vulnerability_type in {"xss", "ssti"}:
        tags.append("raw_output" if _raw_output_signal(lower) else "render_sink")
        required.append("template_binding")
        hints.extend(["find_template_binding", "find_sanitizer"])
    if vulnerability_type in {"file_upload", "file_inclusion", "file_download", "file_path", "path_traversal"}:
        tags.append("file_operation")
        required.extend(["file_save_path", "reachability"])
        hints.extend(["find_file_save_path", "find_path_sanitizer"])
    if vulnerability_type in {"deserialization"} or "unserialize" in lower:
        tags.append("deserialization_sink")
        required.extend(["storage_identity", "reachability"])
        hints.extend(["find_serialized_source", "find_unserialize_guard"])
    if vulnerability_type in {"sql_injection", "nosql_injection"}:
        tags.append("database_sink")
        required.extend(["storage_identity", "sanitizer_state"])
        hints.extend(["find_query_builder", "find_parameterization"])


def _apply_l1_framework_profile(rule: dict[str, Any], language: str, lower: str) -> None:
    tags = rule["semantic_tags"]
    required = rule["required_evidence"]
    hints = rule["repair_hints"]

    if language == "php" and _yeswiki_signal(lower):
        _upgrade(rule, "L1")
        tags.extend(["framework_yeswiki", "framework_entry", "template_engine"])
        required.extend(["permission_check", "template_binding", "storage_identity"])
        hints.extend(["find_yeswiki_action", "find_yeswiki_permission", "find_template_binding"])
        if _config_signal(lower):
            tags.append("config_write_or_read")
            required.append("storage_read")
            hints.append("find_config_storage")
    if language == "python" and _python_framework_signal(lower):
        _upgrade(rule, "L1")
        tags.extend(["python_web_framework", "framework_entry"])
        required.extend(["permission_check", "template_binding"])
        hints.extend(["find_python_route", "find_python_decorator", "find_template_binding"])
        if _orm_signal(lower):
            tags.append("db_persist")
            required.append("storage_identity")
            hints.append("find_orm_field_mapping")
    if language in {"javascript", "typescript"} and _js_framework_signal(lower):
        _upgrade(rule, "L1")
        tags.extend(["js_web_framework", "framework_entry"])
        required.extend(["permission_check", "template_binding"])
        hints.extend(["find_js_route", "find_js_middleware", "find_props_or_template_binding"])


def _apply_l2_shape_profile(rule: dict[str, Any], vulnerability_type: str, lower: str) -> None:
    tags = rule["semantic_tags"]
    required = rule["required_evidence"]
    hints = rule["repair_hints"]

    if vulnerability_type == "xss" and _config_signal(lower) and _html_attr_signal(lower):
        _upgrade(rule, "L2")
        tags.extend(["shape_config_to_raw_html_attr", "nday_family_profile"])
        required.extend(["permission_check", "storage_identity", "template_binding", "sanitizer_state"])
        hints.extend(["find_config_writer", "find_html_attribute_context"])
    if vulnerability_type == "xss" and _content_format_raw_signal(lower):
        _upgrade(rule, "L2")
        tags.extend(["shape_db_content_format_to_raw_template", "nday_family_profile"])
        required.extend(["storage_identity", "storage_read", "template_binding", "sanitizer_state"])
        hints.extend(["find_db_content_write", "find_renderer_format", "find_raw_template_output"])
    if vulnerability_type == "xss" and _filename_js_signal(lower):
        _upgrade(rule, "L2")
        tags.extend(["shape_filename_to_js_string", "nday_family_profile"])
        required.extend(["file_save_path", "template_binding", "sanitizer_state"])
        hints.extend(["find_filename_source", "find_js_string_context"])
    if "unserialize" in lower and _serialized_hidden_import_signal(lower):
        _upgrade(rule, "L2")
        tags.extend(["shape_post_serialized_hidden_unserialize", "nday_family_profile"])
        required.extend(["source_control", "storage_identity", "sanitizer_state"])
        hints.extend(["find_hidden_input_roundtrip", "find_unserialize_guard"])


def _upgrade(rule: dict[str, Any], level: str) -> None:
    rank = {"L0": 0, "L1": 1, "L2": 2}
    current = _normalize_level(rule.get("level"))
    if rank[level] > rank[current]:
        rule["level"] = level


def _normalize_level(value: Any) -> str:
    text = str(value or "L0").upper()
    return text if text in {"L0", "L1", "L2"} else "L0"


def _dedupe(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _raw_output_signal(text: str) -> bool:
    return bool(re.search(r"\becho\b|\bprint\b|\|\s*(raw|safe)\b|innerhtml|dangerouslysetinnerhtml|v-html", text))


def _yeswiki_signal(text: str) -> bool:
    return any(token in text for token in ("yeswiki", "actions/", "performer", "templateengine", "wiki->", "wikirequest"))


def _config_signal(text: str) -> bool:
    return any(token in text for token in ("config", "configuration", "settings", "preset", "preferences"))


def _python_framework_signal(text: str) -> bool:
    return any(token in text for token in ("flask", "django", "render_template", "render(", "@app.route", "urlpatterns"))


def _js_framework_signal(text: str) -> bool:
    return any(token in text for token in ("express", "router.", "app.", "react", "vue", "svelte", "props", "middleware"))


def _orm_signal(text: str) -> bool:
    return any(token in text for token in (".save(", "objects.", "query.", "model", "sqlalchemy", "db.session"))


def _html_attr_signal(text: str) -> bool:
    return bool(re.search(r"\bon[a-z]+\s*=|href\s*=|src\s*=|style\s*=|data-[\w-]+\s*=", text))


def _content_format_raw_signal(text: str) -> bool:
    content_bridge = any(token in text for token in ("content", "comment", "body", "page", "post", "db", "database"))
    renderer = any(token in text for token in ("format(", "formatter", "formatting", "rendercontent", "markdown"))
    return content_bridge and renderer and _raw_output_signal(text)


def _filename_js_signal(text: str) -> bool:
    return ("filename" in text or "basename" in text or "preset" in text) and ("script" in text or "javascript" in text or ".js" in text)


def _serialized_hidden_import_signal(text: str) -> bool:
    return "hidden" in text and ("serialize" in text or "base64" in text or "unserialize" in text)


__all__ = ["BREAKPOINT_EVIDENCE", "enrich_sink_profile"]

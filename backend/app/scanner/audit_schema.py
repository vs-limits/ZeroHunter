from __future__ import annotations

import json
from typing import Any


AUDIT_RESULT_SCHEMA_VERSION = "defectmine.audit.result.v2"

VERDICTS = {"vulnerable", "uncertain", "safe"}
LEGACY_VERDICT_MAP = {
    "confirmed": "vulnerable",
    "true_positive": "vulnerable",
    "not_vulnerable": "safe",
    "false_positive": "safe",
    "needs_review": "uncertain",
    "inconclusive": "uncertain",
    "suspicious": "uncertain",
    "error": "uncertain",
}
CONFIDENCE_LABELS = {"high", "medium", "low"}
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}

REQUIRED_AUDIT_FIELDS = (
    "verdict",
    "confidence",
    "title",
    "cwe_guess",
    "principle",
    "source",
    "sink",
    "data_flow",
    "exploit_poc",
    "fix_suggestion",
    "refuted_by",
    "missing_info",
    "evidence",
)


class AuditSchemaError(ValueError):
    """Raised when Scanner Agent output does not match the strict audit schema."""


AUDIT_RESULT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": True,
    "required": list(REQUIRED_AUDIT_FIELDS),
    "properties": {
        "verdict": {"enum": sorted(VERDICTS)},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "title": {"type": "string"},
        "cwe_guess": {"type": "string"},
        "principle": {"type": "string"},
        "source": {
            "type": "object",
            "properties": {
                "file": {"type": ["string", "null"]},
                "line": {"type": ["integer", "null"]},
                "expr": {"type": ["string", "null"]},
            },
        },
        "sink": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "expr": {"type": "string"},
            },
        },
        "data_flow": {"type": "array", "items": {"type": "string"}},
        "exploit_poc": {"type": "string"},
        "fix_suggestion": {"type": "string"},
        "refuted_by": {"type": ["string", "null"]},
        "missing_info": {"type": "array", "items": {"type": "string"}},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "source": {"enum": ["audit_pack", "tldr", "ripgrep"]},
                    "detail": {"type": "string"},
                    "file": {"type": ["string", "null"]},
                    "line": {"type": ["integer", "null"]},
                },
            },
        },
    },
}


def audit_system_schema_prompt() -> str:
    """Text injected into Scanner system message to force scanner.md-compatible JSON."""
    return (
        "Return exactly one JSON object. Do not wrap it in Markdown. "
        "The JSON must match the scanner.md output schema. Required keys: "
        + ", ".join(REQUIRED_AUDIT_FIELDS)
        + ". verdict must be one of: "
        + ", ".join(sorted(VERDICTS))
        + ". confidence must be a float between 0.0 and 1.0. "
        "All explanatory natural-language fields must be Chinese. "
        "PoC policy: never execute requests, shell commands, database writes, "
        "file writes, or exploit payloads. Only provide a static, non-executed PoC "
        "description in exploit_poc."
    )


def parse_audit_result(raw_output: str, *, chain_id: str = "", analysis_id: str = "") -> dict[str, Any]:
    """Parse, normalize, and validate a Scanner LLM JSON response."""
    data = _parse_json_object(raw_output)
    normalized = normalize_audit_result(data, chain_id=chain_id, analysis_id=analysis_id)
    validate_audit_result(normalized)
    return normalized


def normalize_audit_result(
    data: dict[str, Any],
    *,
    chain_id: str = "",
    analysis_id: str = "",
) -> dict[str, Any]:
    """Normalize new scanner.md results while accepting old v1 audit artifacts."""
    result = dict(data)

    result["schema_version"] = AUDIT_RESULT_SCHEMA_VERSION
    result["chain_id"] = str(result.get("chain_id") or chain_id)
    result["analysis_id"] = str(result.get("analysis_id") or analysis_id)
    result["verdict"] = _normalize_verdict(result.get("verdict"))
    result["confidence"], result["confidence_label"] = _normalize_confidence(result.get("confidence"))
    result["severity"] = _normalize_severity(result.get("severity"))
    result.setdefault("title", _default_title(result))
    result.setdefault("cwe_guess", _default_cwe(result))
    result.setdefault("principle", "")
    result["source"] = _normalize_location(result.get("source"), allow_empty=True)
    result["sink"] = _normalize_location(result.get("sink"), allow_empty=False)
    result["data_flow"] = _normalize_string_list(result.get("data_flow"))
    result.setdefault("exploit_poc", "")
    result.setdefault("fix_suggestion", "")
    result["refuted_by"] = _normalize_nullable_string(result.get("refuted_by"))
    result["missing_info"] = _normalize_string_list(result.get("missing_info"))
    result["evidence"] = _normalize_evidence(result.get("evidence"))
    result["tool_rounds"] = _normalize_list(result.get("tool_rounds"))

    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    result["meta"] = {
        **meta,
        "chain_id": result["chain_id"],
        "analysis_id": result["analysis_id"],
        "severity": result["severity"],
    }
    return result


def validate_audit_result(result: dict[str, Any]) -> None:
    if not isinstance(result, dict):
        raise AuditSchemaError("audit result must be an object")
    missing = [key for key in REQUIRED_AUDIT_FIELDS if key not in result]
    if missing:
        raise AuditSchemaError(f"audit result missing keys: {', '.join(missing)}")
    if result.get("verdict") not in VERDICTS:
        raise AuditSchemaError(f"invalid verdict: {result.get('verdict')!r}")
    confidence = result.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
        raise AuditSchemaError(f"invalid confidence: {confidence!r}")
    if result.get("severity") not in SEVERITIES:
        raise AuditSchemaError(f"invalid severity: {result.get('severity')!r}")
    for key in ("title", "cwe_guess", "principle", "exploit_poc", "fix_suggestion"):
        if not isinstance(result.get(key), str):
            raise AuditSchemaError(f"{key} must be a string")
    if result.get("refuted_by") is not None and not isinstance(result.get("refuted_by"), str):
        raise AuditSchemaError("refuted_by must be a string or null")
    if not isinstance(result.get("source"), dict):
        raise AuditSchemaError("source must be an object")
    if not isinstance(result.get("sink"), dict):
        raise AuditSchemaError("sink must be an object")
    if not isinstance(result.get("data_flow"), list):
        raise AuditSchemaError("data_flow must be a list")
    if not isinstance(result.get("evidence"), list):
        raise AuditSchemaError("evidence must be a list")
    if not isinstance(result.get("missing_info"), list):
        raise AuditSchemaError("missing_info must be a list")


def error_audit_result(
    *,
    chain_id: str,
    analysis_id: str,
    message: str,
    severity: str = "unknown",
) -> dict[str, Any]:
    return normalize_audit_result(
        {
            "chain_id": chain_id,
            "analysis_id": analysis_id,
            "verdict": "uncertain",
            "confidence": 0.0,
            "severity": severity,
            "title": "Scanner Agent 未能完成结构化审计",
            "cwe_guess": "unknown",
            "principle": "Scanner Agent 未能完成结构化审计，不能给出漏洞结论。",
            "source": {"file": None, "line": None, "expr": None},
            "sink": {"file": "", "line": 0, "expr": ""},
            "data_flow": [],
            "exploit_poc": "未生成 PoC；本次审计没有形成可验证结论。",
            "fix_suggestion": "请补充调用链上下文或重新运行审计。",
            "refuted_by": None,
            "missing_info": [message],
            "evidence": [],
            "tool_rounds": [],
            "meta": {"status": "error"},
        },
        chain_id=chain_id,
        analysis_id=analysis_id,
    )


def _normalize_verdict(value: Any) -> str:
    verdict = str(value or "").strip().lower()
    if verdict in VERDICTS:
        return verdict
    return LEGACY_VERDICT_MAP.get(verdict, "uncertain")


def _normalize_confidence(value: Any) -> tuple[float, str]:
    if isinstance(value, (int, float)):
        confidence = max(0.0, min(1.0, float(value)))
        return confidence, _confidence_label(confidence)

    text = str(value or "").strip().lower()
    if text in CONFIDENCE_LABELS:
        mapped = {"high": 0.85, "medium": 0.6, "low": 0.3}[text]
        return mapped, text
    try:
        confidence = max(0.0, min(1.0, float(text)))
    except ValueError:
        confidence = 0.0
    return confidence, _confidence_label(confidence)


def _confidence_label(value: float) -> str:
    if value >= 0.75:
        return "high"
    if value >= 0.45:
        return "medium"
    return "low"


def _normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in SEVERITIES else "unknown"


def _normalize_location(value: Any, *, allow_empty: bool) -> dict[str, Any]:
    if isinstance(value, dict):
        return {
            "file": _normalize_nullable_string(value.get("file")),
            "line": _normalize_int_or_none(value.get("line")),
            "expr": _normalize_nullable_string(value.get("expr")),
        }
    return {
        "file": None if allow_empty else "",
        "line": None if allow_empty else 0,
        "expr": None if allow_empty else "",
    }


def _normalize_evidence(value: Any) -> list[dict[str, Any]]:
    items = _normalize_list(value)
    evidence: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            source = str(item.get("source") or "audit_pack")
            if source not in {"audit_pack", "tldr", "ripgrep"}:
                source = "audit_pack"
            evidence.append(
                {
                    "source": source,
                    "detail": str(
                        item.get("detail")
                        or item.get("description")
                        or item.get("reason")
                        or item.get("text")
                        or item.get("evidence")
                        or ""
                    ),
                    "file": _normalize_nullable_string(item.get("file") or item.get("path") or item.get("location")),
                    "line": _normalize_int_or_none(item.get("line") or item.get("line_number")),
                }
            )
        else:
            evidence.append({"source": "audit_pack", "detail": str(item), "file": None, "line": None})
    return evidence


def _normalize_string_list(value: Any) -> list[str]:
    return [str(item) for item in _normalize_list(value) if str(item).strip()]


def _normalize_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_nullable_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _normalize_int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _default_title(result: dict[str, Any]) -> str:
    cwe = result.get("cwe_guess") or result.get("vulnerability_type") or "unknown"
    sink = result.get("sink")
    if isinstance(sink, dict) and sink.get("file"):
        return f"{cwe} @ {sink.get('file')}:{sink.get('line') or 0}"
    return str(cwe)


def _default_cwe(result: dict[str, Any]) -> str:
    return str(result.get("cwe_guess") or result.get("vulnerability_type") or result.get("vuln_type") or "unknown")


def _parse_json_object(raw: str) -> dict[str, Any]:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = _strip_code_fence(cleaned)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        parsed = json.loads(_extract_json_object(cleaned))
    if not isinstance(parsed, dict):
        raise AuditSchemaError("audit response must be a JSON object")
    return parsed


def _strip_code_fence(text: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _extract_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise AuditSchemaError("audit response does not contain a JSON object")
    return text[start : end + 1]


__all__ = [
    "AUDIT_RESULT_SCHEMA_VERSION",
    "AUDIT_RESULT_JSON_SCHEMA",
    "AuditSchemaError",
    "audit_system_schema_prompt",
    "parse_audit_result",
    "normalize_audit_result",
    "validate_audit_result",
    "error_audit_result",
]

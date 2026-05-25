from __future__ import annotations

import re
from typing import Any


SEVERITY_SCORE = {
    "critical": 35,
    "high": 25,
    "medium": 15,
    "low": 8,
}

VULNERABILITY_SCORE = {
    "command_execution": 25,
    "code_execution": 25,
    "sql_injection": 20,
    "deserialization": 18,
    "file_inclusion": 18,
    "file_upload": 18,
    "path_traversal": 16,
    "file_download": 15,
    "ssrf": 15,
    "xss": 14,
    "xxe": 14,
    "nosql_injection": 14,
    "graphql_injection": 12,
    "xpath_injection": 12,
    "ldap_injection": 12,
    "auth_bypass": 12,
    "unauthorized_access": 12,
    "weak_credential": 8,
    "info_disclosure": 8,
    "csrf": 8,
    "crlf_injection": 8,
    "ssti": 16,
    "buffer_overflow": 18,
}

HIGH_VALUE_PATH_RE = re.compile(
    r"(^|/)(actions?|controllers?|api|routes?|handlers?|services?|admin|auth|login|upload|database|sql|install)(/|$)",
    re.IGNORECASE,
)
LOW_VALUE_PATH_RE = re.compile(
    r"(^|/)(docs?|examples?|samples?|tests?|specs?|fixtures?|deprecated|backup|_old|cache|tmp)(/|$)",
    re.IGNORECASE,
)
ENTRY_PATH_RE = re.compile(r"(^|/)(actions?|controllers?|api|routes?|handlers?)(/|$)", re.IGNORECASE)
ENTRY_NAME_RE = re.compile(r"(run|execute|dispatch|handle|action|controller|route|hook|__invoke)", re.IGNORECASE)

EXTERNAL_SOURCE_RE = re.compile(
    r"(\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)|\brequest(?:\.|->)|\bparams?\b|\bquery\b|\bheaders?\b|\bcookies?\b|\bbody\b|\bargv\b|\bstdin\b|\bgetenv\s*\()",
    re.IGNORECASE,
)
SANITIZER_RE = re.compile(
    r"\b(intval|floatval|boolval|htmlspecialchars|htmlentities|strip_tags|filter_var|"
    r"mysqli_real_escape_string|pg_escape_string|sqlite_escape_string|addslashes|"
    r"basename|realpath|wp_kses|esc_html|esc_attr|escape|sanitize_[a-z0-9_]+|"
    r"preg_match|in_array|array_key_exists)\s*\(",
    re.IGNORECASE,
)
SQL_BIND_RE = re.compile(r"\b(bindParam|bindValue|execute\s*\(\s*\[|prepare\s*\()", re.IGNORECASE)
VARIABLE_RE = re.compile(r"(\$\w+|[A-Za-z_][A-Za-z0-9_]*\s*(?:\.|->|\[))")


def rank_impact_paths(
    *,
    complete_impact_paths: list[dict[str, Any]],
    sink_analyses: list[dict[str, Any]],
    sink_rules: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Score complete source-to-sink candidates for Scanner Agent scheduling.

    Ranking is intentionally heuristic and deterministic: CallScan only decides
    audit order here. It does not decide whether a vulnerability is real.
    """
    analyses_by_id = {
        str(analysis.get("analysis_id", "")): analysis
        for analysis in sink_analyses
        if isinstance(analysis, dict)
    }
    rules_by_id = {
        str(rule.get("id", "")): rule
        for rule in (sink_rules or [])
        if isinstance(rule, dict)
    }

    ranked: list[dict[str, Any]] = []
    for path in complete_impact_paths:
        analysis = analyses_by_id.get(str(path.get("analysis_id", "")), {})
        ranked.append(_rank_one_path(path, analysis, rules_by_id))

    return sorted(
        ranked,
        key=lambda item: (
            -int(item.get("risk_score", 0)),
            str(_object_or_empty(item.get("sink")).get("file", "")),
            int(_object_or_empty(item.get("sink")).get("line", 0) or 0),
            str(item.get("path_id", "")),
        ),
    )


def attach_rank_to_audit_pack(audit_pack: dict[str, Any], ranked_path: dict[str, Any]) -> dict[str, Any]:
    """Put ranking metadata beside the rendered code pack consumed by Scanner."""
    audit_pack["rank"] = {
        "risk_score": ranked_path.get("risk_score", 0),
        "risk_level": ranked_path.get("risk_level", "low"),
        "priority": ranked_path.get("priority", "P3"),
        "positive_reasons": ranked_path.get("positive_reasons", []),
        "negative_reasons": ranked_path.get("negative_reasons", []),
        "uncertainty_reasons": ranked_path.get("uncertainty_reasons", []),
    }
    audit_pack["sink"] = ranked_path.get("sink", {})
    audit_pack["entry"] = ranked_path.get("entry", {})
    return audit_pack


def select_scanner_queue(
    ranked_impact_paths: list[dict[str, Any]],
    *,
    limit: int = 20,
    per_analysis_limit: int = 1,
) -> list[dict[str, Any]]:
    """Pick a diverse high-priority queue without losing the full ranking.

    Multiple complete chains may point to the same sink. For the Scanner queue,
    we first prefer one best path per analysis_id, then fill remaining slots if
    the project has fewer unique sinks than the requested limit.
    """
    selected: list[dict[str, Any]] = []
    analysis_counts: dict[str, int] = {}

    for item in ranked_impact_paths:
        analysis_id = str(item.get("analysis_id", ""))
        if analysis_counts.get(analysis_id, 0) >= per_analysis_limit:
            continue
        selected.append(item)
        analysis_counts[analysis_id] = analysis_counts.get(analysis_id, 0) + 1
        if len(selected) >= limit:
            return selected

    seen_paths = {str(item.get("path_id", "")) for item in selected}
    for item in ranked_impact_paths:
        path_id = str(item.get("path_id", ""))
        if path_id in seen_paths:
            continue
        selected.append(item)
        if len(selected) >= limit:
            return selected
    return selected


def _rank_one_path(
    path: dict[str, Any],
    analysis: dict[str, Any],
    rules_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    sink = _object_or_empty(analysis.get("sink"))
    location = _object_or_empty(analysis.get("location"))
    backward_slice = _object_or_empty(analysis.get("backward_slice"))
    sink_id = str(sink.get("sink_id", ""))
    rule = rules_by_id.get(sink_id, {})
    language = str(analysis.get("language") or rule.get("language") or _language_from_sink_id(sink_id) or "unknown")

    score = 0
    positive: list[str] = []
    negative: list[str] = []
    uncertainty: list[str] = []

    severity = str(rule.get("severity") or sink.get("severity") or "medium").casefold()
    score += _add_reason(positive, f"{severity} severity sink", SEVERITY_SCORE.get(severity, 15))

    vulnerability = str(sink.get("vulnerability") or rule.get("vulnerability") or "")
    vuln_score = VULNERABILITY_SCORE.get(vulnerability, 10)
    score += _add_reason(positive, f"{vulnerability or 'generic'} sink category", vuln_score)

    score += _score_data_flow(backward_slice, positive, negative, uncertainty)
    score += _score_entry(path, positive, negative)
    score += _score_paths(path, location, positive, negative)
    score += _score_edges(path, uncertainty)

    score = max(0, min(100, score))
    return {
        "path_id": path.get("path_id", ""),
        "analysis_id": path.get("analysis_id", ""),
        "risk_score": score,
        "risk_level": _risk_level(score),
        "priority": _priority(score),
        "sink": {
            "sink_id": sink_id,
            "language": language,
            "function": sink.get("match", ""),
            "category": sink.get("category", rule.get("category", "")),
            "vulnerability": vulnerability,
            "vulnerability_type": vulnerability,
            "severity": severity,
            "file": location.get("file", ""),
            "line": sink.get("line", location.get("sink_line", 0)),
            "evidence": sink.get("evidence", ""),
            "sink_argument": backward_slice.get("sink_argument", ""),
        },
        "entry": _entry_summary(path),
        "data_flow": {
            "source_candidates": backward_slice.get("source_candidates", []),
            "tracked_symbols": backward_slice.get("tracked_symbols", []),
            "unresolved_symbols": backward_slice.get("unresolved_symbols", []),
            "slice_confidence": backward_slice.get("confidence", "unknown"),
        },
        "positive_reasons": positive,
        "negative_reasons": negative,
        "uncertainty_reasons": uncertainty,
        "path": path,
    }


def _score_data_flow(
    backward_slice: dict[str, Any],
    positive: list[str],
    negative: list[str],
    uncertainty: list[str],
) -> int:
    score = 0
    sink_argument = str(backward_slice.get("sink_argument", ""))
    slice_text = " ".join(
        [
            sink_argument,
            *[str(item.get("evidence", "")) for item in _list_of_dicts(backward_slice.get("source_candidates"))],
            *[str(item.get("text", "")) for item in _list_of_dicts(backward_slice.get("assignments"))],
        ]
    )

    source_candidates = _list_of_dicts(backward_slice.get("source_candidates"))
    if source_candidates:
        if EXTERNAL_SOURCE_RE.search(slice_text):
            score += _add_reason(positive, "external input evidence reaches sink slice", 25)
        else:
            score += _add_reason(positive, "source candidate found by local backward slice", 15)
        if any(str(item.get("kind", "")) == "function-parameter" for item in source_candidates):
            score += _add_reason(positive, "sink data flows through function parameter", 10)
    else:
        uncertainty.append("no source candidate in local backward slice")
        score += 3

    confidence = str(backward_slice.get("confidence", "")).casefold()
    if confidence == "high":
        score += _add_reason(positive, "high-confidence local slice", 5)
    elif confidence == "medium":
        score += _add_reason(positive, "medium-confidence local slice", 3)
    else:
        uncertainty.append("low-confidence local slice")

    if _looks_constant(sink_argument):
        score -= _add_negative_reason(negative, "sink argument appears constant", 25)
    if SANITIZER_RE.search(slice_text):
        score -= _add_negative_reason(negative, "sanitizer or validator appears in sink slice", 20)
    if SQL_BIND_RE.search(slice_text):
        score -= _add_negative_reason(negative, "prepared/bound SQL evidence lowers exploitability", 15)

    unresolved = backward_slice.get("unresolved_symbols", [])
    if isinstance(unresolved, list) and unresolved:
        uncertainty.append(f"{len(unresolved)} unresolved symbol(s) in local slice")
        score -= min(10, len(unresolved) * 2)

    return score


def _score_entry(path: dict[str, Any], positive: list[str], negative: list[str]) -> int:
    entry = _entry_summary(path)
    entry_file = str(entry.get("file", ""))
    entry_function = str(entry.get("function", ""))
    if ENTRY_PATH_RE.search(entry_file) or ENTRY_NAME_RE.search(entry_function):
        return _add_reason(positive, "chain reaches route/action/controller style entry", 20)
    if "install" in entry_file.casefold() or "setup" in entry_file.casefold():
        return _add_reason(positive, "chain reaches install/setup entry", 8)
    negative.append("entry node is generic internal code")
    return 0


def _score_paths(
    path: dict[str, Any],
    location: dict[str, Any],
    positive: list[str],
    negative: list[str],
) -> int:
    score = 0
    files = [str(location.get("file", ""))]
    files.extend(str(_object_or_empty(node).get("file", "")) for node in path.get("nodes", []))
    joined = " ".join(files)
    if HIGH_VALUE_PATH_RE.search(joined):
        score += _add_reason(positive, "high-value application path", 10)
    if LOW_VALUE_PATH_RE.search(joined):
        score -= _add_negative_reason(negative, "low-value test/docs/generated path", 25)
    return score


def _score_edges(path: dict[str, Any], uncertainty: list[str]) -> int:
    edges = _list_of_dicts(path.get("edges"))
    if not edges:
        uncertainty.append("no call edge evidence")
        return -5
    medium_edges = sum(1 for edge in edges if str(edge.get("confidence", "")).casefold() == "medium")
    low_edges = sum(1 for edge in edges if str(edge.get("confidence", "")).casefold() == "low")
    dynamic_edges = sum(1 for edge in edges if "dynamic" in str(edge.get("kind", "")).casefold())
    penalty = min(10, medium_edges * 2 + low_edges * 5 + dynamic_edges * 5)
    if penalty:
        uncertainty.append("call chain contains static or uncertain edge evidence")
    return -penalty


def _entry_summary(path: dict[str, Any]) -> dict[str, Any]:
    nodes = _list_of_dicts(path.get("nodes"))
    entry = nodes[-1] if nodes else {}
    function = str(entry.get("function", "") or entry.get("name", ""))
    file = str(entry.get("file", ""))
    if ENTRY_PATH_RE.search(file) or ENTRY_NAME_RE.search(function):
        kind = "route-or-action"
    elif "install" in file.casefold() or "setup" in file.casefold():
        kind = "install-or-setup"
    else:
        kind = "generic-entry"
    return {
        "kind": kind,
        "file": file,
        "function": function,
        "function_ref": entry.get("function_ref", ""),
    }


def _looks_constant(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if EXTERNAL_SOURCE_RE.search(text):
        return False
    if VARIABLE_RE.search(text):
        return False
    return bool(re.fullmatch(r"[\s\[\]\(\),.'\":/\\A-Za-z0-9_-]+", text))


def _language_from_sink_id(sink_id: str) -> str:
    prefix = sink_id.split("-", 1)[0].casefold()
    return {
        "js": "javascript",
        "ts": "typescript",
        "py": "python",
    }.get(prefix, prefix)


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _priority(score: int) -> str:
    if score >= 80:
        return "P0"
    if score >= 60:
        return "P1"
    if score >= 35:
        return "P2"
    return "P3"


def _add_reason(reasons: list[str], reason: str, points: int) -> int:
    reasons.append(f"{reason} (+{points})")
    return points


def _add_negative_reason(reasons: list[str], reason: str, points: int) -> int:
    reasons.append(f"{reason} (-{points})")
    return points


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


PRIORITY_CHAIN_SCHEMA_VERSION = "defectmine.callscan.priority_chain.v1"

REQUIRED_TOP_LEVEL_KEYS = (
    "schema_version",
    "priority_index",
    "path_id",
    "analysis_id",
    "language",
    "vulnerability_type",
    "rank",
    "sink",
    "entry",
    "chain",
    "call_edges",
    "functions",
)

REQUIRED_RANK_KEYS = ("risk_score", "risk_level", "priority")
REQUIRED_SINK_KEYS = ("sink_id", "language", "vulnerability_type", "category", "file", "line")
REQUIRED_ENTRY_KEYS = ("kind", "file", "function")


class PriorityChainSchemaError(ValueError):
    """Raised when callscan_chains.priority.jsonl contains an invalid record."""


def priority_chain_record_from_audit_pack(index: int, pack: dict[str, Any]) -> dict[str, Any]:
    """Build the stable JSONL record consumed by Scanner Agent."""
    sink = _object_or_empty(pack.get("sink"))
    vulnerability_type = str(
        sink.get("vulnerability_type") or sink.get("vulnerability") or "unknown"
    )
    language = str(sink.get("language") or _language_from_sink_id(str(sink.get("sink_id", ""))) or "unknown")
    normalized_sink = {
        **sink,
        "language": language,
        "vulnerability_type": vulnerability_type,
    }
    if "vulnerability" not in normalized_sink:
        normalized_sink["vulnerability"] = vulnerability_type

    record = {
        "schema_version": PRIORITY_CHAIN_SCHEMA_VERSION,
        "priority_index": int(index),
        "path_id": str(pack.get("path_id", "")),
        "analysis_id": str(pack.get("analysis_id", "")),
        "language": language,
        "vulnerability_type": vulnerability_type,
        "rank": _object_or_empty(pack.get("rank")),
        "sink": normalized_sink,
        "entry": _object_or_empty(pack.get("entry")),
        "chain": _list_of_dicts(pack.get("chain")),
        "call_edges": _list_of_dicts(pack.get("call_edges")),
        "functions": _list_of_dicts(pack.get("functions")),
    }
    validate_priority_chain_record(record)
    return record


def validate_priority_chain_record(record: dict[str, Any]) -> None:
    """Validate the fixed priority-chain JSONL schema without extra dependencies."""
    if not isinstance(record, dict):
        raise PriorityChainSchemaError("priority chain record must be an object")

    _require_keys(record, REQUIRED_TOP_LEVEL_KEYS, "priority chain record")
    if record.get("schema_version") != PRIORITY_CHAIN_SCHEMA_VERSION:
        raise PriorityChainSchemaError(
            f"unsupported schema_version: {record.get('schema_version')!r}"
        )
    if int(record.get("priority_index", 0) or 0) <= 0:
        raise PriorityChainSchemaError("priority_index must be a positive integer")
    if not str(record.get("path_id", "")).strip():
        raise PriorityChainSchemaError("path_id is required")
    if not str(record.get("analysis_id", "")).strip():
        raise PriorityChainSchemaError("analysis_id is required")
    if not str(record.get("language", "")).strip():
        raise PriorityChainSchemaError("language is required")
    if not str(record.get("vulnerability_type", "")).strip():
        raise PriorityChainSchemaError("vulnerability_type is required")

    rank = _object_or_empty(record.get("rank"))
    sink = _object_or_empty(record.get("sink"))
    entry = _object_or_empty(record.get("entry"))
    _require_keys(rank, REQUIRED_RANK_KEYS, "rank")
    _require_keys(sink, REQUIRED_SINK_KEYS, "sink")
    _require_keys(entry, REQUIRED_ENTRY_KEYS, "entry")

    if not isinstance(record.get("chain"), list):
        raise PriorityChainSchemaError("chain must be a list")
    if not isinstance(record.get("call_edges"), list):
        raise PriorityChainSchemaError("call_edges must be a list")
    if not isinstance(record.get("functions"), list):
        raise PriorityChainSchemaError("functions must be a list")


def load_priority_chain_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Load and validate callscan_chains.priority.jsonl for Scanner Agent."""
    records: list[dict[str, Any]] = []
    jsonl_path = Path(path)
    for line_number, line in enumerate(jsonl_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PriorityChainSchemaError(f"invalid JSONL at line {line_number}: {exc}") from exc
        try:
            validate_priority_chain_record(record)
        except PriorityChainSchemaError as exc:
            raise PriorityChainSchemaError(f"invalid priority chain at line {line_number}: {exc}") from exc
        records.append(record)
    return records


def validate_priority_chain_records(records: Iterable[dict[str, Any]]) -> None:
    for record in records:
        validate_priority_chain_record(record)


def _require_keys(data: dict[str, Any], keys: tuple[str, ...], label: str) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        raise PriorityChainSchemaError(f"{label} missing required keys: {', '.join(missing)}")


def _language_from_sink_id(sink_id: str) -> str:
    prefix = sink_id.split("-", 1)[0].casefold()
    return {
        "js": "javascript",
        "ts": "typescript",
        "py": "python",
    }.get(prefix, prefix)


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]

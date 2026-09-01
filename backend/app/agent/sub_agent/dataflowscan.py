"""DataFlowScan Agent: recover cross-request source -> storage -> sink chains."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

from app.agent.logger import write_event
from app.agent.run_scope import RunScope, resolve_run_scope
from app.scanner.rules import should_skip_for_scan
from app.ui.console import action, info


DATAFLOW_GRAPH_JSON = "dataflow_graph.json"
CROSS_REQUEST_CHAINS_JSONL = "cross_request_chains.jsonl"
CALLSCAN_CHAINS_JSONL = "callscan_chains.jsonl"
CALLSCAN_PRIORITY_JSONL = "callscan_chains.priority.jsonl"

SOURCE_NODE = "request_source"
HANDLER_NODE = "handler"
STORAGE_NODE = "storage_field"
TEMPLATE_NODE = "template_var"
SINK_NODE = "sink"

QUALITY_CONFIRMED = "confirmed"
QUALITY_PROBABLE = "probable"
QUALITY_WEAK = "weak"

SUPPORTED_SUFFIXES = {
    ".py",
    ".php",
    ".html",
    ".htm",
    ".jinja",
    ".jinja2",
    ".tpl",
    ".twig",
    ".phtml",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
}

SOURCE_PATTERNS = {
    "python": re.compile(
        r"\brequest\.(?:form|args|values|json|files|cookies|get_json)\b|request\s*\[",
        re.IGNORECASE,
    ),
    "php": re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b", re.IGNORECASE),
    "javascript": re.compile(
        r"\b(?:req|request)\.(?:body|query|params|cookies|files)\b|"
        r"\b(?:URLSearchParams|location\.search|document\.cookie|FormData)\b|"
        r"\b(?:fetch|axios)\s*\(",
        re.IGNORECASE,
    ),
}
PY_LOCAL_ASSIGN_RE = re.compile(
    r"^\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*(?P<expr>.+?)\s*$"
)
PY_FIELD_ASSIGN_RE = re.compile(
    r"^\s*(?P<object>[A-Za-z_][A-Za-z0-9_]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*(?P<expr>.+?)\s*$"
)
PY_CTOR_RE = re.compile(r"\b(?P<model>[A-Z][A-Za-z0-9_]*)\s*\((?P<args>.*)\)")
PY_KWARG_RE = re.compile(r"\b(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^,\n\r)]+)")
PY_RENDER_RE = re.compile(
    r"\brender_template\s*\(\s*['\"](?P<template>[^'\"]+)['\"](?P<args>[\s\S]*?)\)",
    re.MULTILINE,
)
TEMPLATE_SAFE_RE = re.compile(
    r"\{\{\s*(?P<expr>[^{}]+?)\s*\|\s*(?:safe|raw)\b[^{}]*\}\}",
    re.IGNORECASE,
)
PHP_ECHO_RE = re.compile(r"\b(?:echo|print)\s+(?P<expr>[^;]+);", re.IGNORECASE)
PHP_ASSIGN_RE = re.compile(
    r"^\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*(?P<expr>.+?)\s*;?\s*$"
)
PHP_OBJECT_ASSIGN_RE = re.compile(
    r"^\s*\$(?P<object>[A-Za-z_][A-Za-z0-9_]*)\s*->\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*(?P<expr>.+?)\s*;?\s*$"
)
PHP_ARRAY_ASSIGN_RE = re.compile(
    r"^\s*\$(?P<object>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*['\"](?P<field>[^'\"]+)['\"]\s*\]\s*=(?!=)\s*(?P<expr>.+?)\s*;?\s*$"
)
JS_LOCAL_ASSIGN_RE = re.compile(
    r"^\s*(?:const|let|var)?\s*(?P<target>[A-Za-z_$][A-Za-z0-9_$]*)\s*=(?!=)\s*(?P<expr>.+?)\s*;?\s*$"
)
JS_PROP_ASSIGN_RE = re.compile(
    r"^\s*(?P<object>[A-Za-z_$][A-Za-z0-9_$]*)\.(?P<field>[A-Za-z_$][A-Za-z0-9_$]*)\s*=(?!=)\s*(?P<expr>.+?)\s*;?\s*$"
)
JS_STORAGE_SET_RE = re.compile(
    r"\b(?P<store>localStorage|sessionStorage)\.setItem\s*\(\s*['\"](?P<key>[^'\"]+)['\"]\s*,\s*(?P<expr>.+?)\s*\)",
    re.IGNORECASE,
)
JS_STORAGE_GET_RE = re.compile(
    r"\b(?P<store>localStorage|sessionStorage)\.getItem\s*\(\s*['\"](?P<key>[^'\"]+)['\"]\s*\)",
    re.IGNORECASE,
)
JS_INNERHTML_RE = re.compile(
    r"\b(?:innerHTML|outerHTML)\s*=(?!=)\s*(?P<expr>.+?)\s*;?$|"
    r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?P<react>[^}]+)\}\s*\}|"
    r"\bv-html\s*=\s*['\"](?P<vue>[^'\"]+)['\"]",
    re.IGNORECASE,
)
SQL_INSERT_RE = re.compile(
    r"insert\s+into\s+`?(?P<table>[A-Za-z0-9_]+)`?\s*\((?P<columns>[^)]+)\)",
    re.IGNORECASE,
)
SQL_UPDATE_RE = re.compile(
    r"update\s+`?(?P<table>[A-Za-z0-9_]+)`?\s+set\s+(?P<sets>.+?)(?:\s+where|\)|;|$)",
    re.IGNORECASE,
)
SQL_SELECT_RE = re.compile(
    r"select\s+(?P<columns>.+?)\s+from\s+`?(?P<table>[A-Za-z0-9_]+)`?",
    re.IGNORECASE,
)
FILE_WRITE_RE = re.compile(
    r"\b(?:file_put_contents|fwrite|move_uploaded_file)\s*\(|\.save\s*\(|\bopen\s*\([^)]*[\"'](?:w|a|x|wb|ab)[\"']",
    re.IGNORECASE,
)
FILE_READ_RE = re.compile(
    r"\b(?:include|include_once|require|require_once|readfile|send_file|send_from_directory)\s*\(|\bopen\s*\([^)]*[\"'](?:r|rb)[\"']",
    re.IGNORECASE,
)
SANITIZER_RE = re.compile(
    r"\b(?:escape|escaped|htmlspecialchars|htmlentities|sanitize|clean|bleach|markupsafe\.escape)\b",
    re.IGNORECASE,
)
STRONG_SANITIZER_RE = re.compile(
    r"\b(?:htmlspecialchars|htmlentities|markupsafe\.escape|bleach\.clean|escape|"
    r"secure_filename|basename|realpath|path\.resolve|parameterized|prepare|"
    r"execute\s*\([^)]*,\s*(?:\(|\[|\{)|bind_param|bindValue|bindParam)\b",
    re.IGNORECASE,
)
WEAK_SANITIZER_RE = re.compile(
    r"\b(?:strip_tags|strip|trim|replace|str_replace|preg_replace|filter_var)\b",
    re.IGNORECASE,
)
RAW_XSS_SINK_RE = re.compile(
    r"\|\s*(?:safe|raw)\b|dangerouslySetInnerHTML|v-html\b|innerHTML\s*=",
    re.IGNORECASE,
)
FILE_UPLOAD_SOURCE_RE = re.compile(
    r"\brequest\.files\b|\$_FILES\b|multipart|multer|MultipartFile",
    re.IGNORECASE,
)
FILE_NAME_SANITIZER_RE = re.compile(
    r"\b(?:secure_filename|basename|realpath|path\.resolve|normalize|sanitize)\b",
    re.IGNORECASE,
)
EXTENSION_POLICY_RE = re.compile(
    r"\b(?:allowed_extensions?|allowed_file|mimetypes?|content_type|endswith|"
    r"pathinfo|extension|extname)\b",
    re.IGNORECASE,
)
WEB_ACCESSIBLE_PATH_RE = re.compile(
    r"\b(?:static|public|uploads?|wwwroot|htdocs|webroot|media)\b",
    re.IGNORECASE,
)


def run(project_path: str, run_id: str | None = None) -> dict[str, Any]:
    started_at = time.perf_counter()
    scope = resolve_run_scope(project_path, run_id)
    project_root = scope.project_root
    output_json = scope.artifacts_dir / DATAFLOW_GRAPH_JSON
    output_jsonl = scope.artifacts_dir / CROSS_REQUEST_CHAINS_JSONL

    info("DataFlowScan: scanning source/storage/sink bridges")
    write_event("dataflowscan_start", project_path=project_path, run_id=run_id)

    callscan_chains = _load_callscan_records(scope.artifacts_dir)
    graph = _extract_dataflow_graph(project_root, scope)
    chains = _build_cross_request_chains(graph, callscan_chains)
    graph["cross_request_chains"] = chains
    graph["summary"] = _build_summary(graph, chains, started_at)
    if graph["summary"].get("cross_request_chains", 0):
        graph["status"] = "ok"
    elif graph["summary"].get("recovered_partial", 0):
        graph["status"] = "partial_only"
    else:
        graph["status"] = "no_cross_request_chains"
    graph["project_path"] = project_path
    graph["project_root"] = str(project_root)
    graph["scope"] = scope.to_dict()

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(graph, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    action("Write", str(output_json))

    written = _write_cross_request_jsonl(
        output_jsonl,
        chains,
        project_path=project_path,
        scope=scope,
    )
    action("Write", f"{output_jsonl} ({written} chain(s))")

    write_event(
        "dataflowscan_end",
        project_path=project_path,
        run_id=run_id,
        summary=graph["summary"],
        elapsed=time.perf_counter() - started_at,
    )
    info(
        "DataFlowScan: "
        f"{graph['summary']['cross_request_chains']} cross-request chain(s), "
        f"{graph['summary']['recovered_partial']} recovered partial chain(s), "
        f"{graph['summary']['storage_nodes']} storage node(s)"
    )
    return graph


def _load_callscan_records(artifacts_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    full_path = artifacts_dir / CALLSCAN_CHAINS_JSONL
    legacy_priority_path = artifacts_dir / CALLSCAN_PRIORITY_JSONL
    path = full_path if full_path.is_file() else legacy_priority_path
    if not path.is_file():
        return records

    seen: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("type") != "chain":
                continue
            chain_id = str(item.get("chain_id") or item.get("id") or "").strip()
            if chain_id and chain_id in seen:
                continue
            if chain_id:
                seen.add(chain_id)
            records.append(item)
    return records


def _extract_dataflow_graph(project_root: Path, scope: RunScope) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    writes: list[dict[str, Any]] = []
    reads: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    breakpoints: list[dict[str, Any]] = []

    def add_node(node: dict[str, Any]) -> dict[str, Any]:
        nodes[node["node_id"]] = {**nodes.get(node["node_id"], {}), **node}
        return nodes[node["node_id"]]

    def add_edge(edge: dict[str, Any]) -> None:
        edges[edge["edge_id"]] = edge

    for path in _iter_source_files(project_root, scope):
        rel = _rel_path(project_root, path)
        language = _language_for_path(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        if language == "python":
            file_items = _extract_python_file(rel, text, lines)
        elif language == "php":
            file_items = _extract_php_file(rel, text, lines)
        elif language == "javascript":
            file_items = _extract_javascript_file(rel, text, lines)
        else:
            file_items = _extract_template_file(rel, lines)

        for node in file_items["nodes"]:
            add_node(node)
        for edge in file_items["edges"]:
            add_edge(edge)
        writes.extend(file_items["writes"])
        reads.extend(file_items["reads"])
        sinks.extend(file_items["sinks"])
        breakpoints.extend(file_items["breakpoints"])

    return {
        "schema_version": "defectmine.dataflowscan.graph.v2",
        "nodes": sorted(nodes.values(), key=lambda n: (n.get("file", ""), int(n.get("line") or 0), n["node_id"])),
        "edges": sorted(edges.values(), key=lambda e: (e.get("file", ""), int(e.get("line") or 0), e["edge_id"])),
        "writes": writes,
        "reads": reads,
        "sinks": sinks,
        "breakpoints": _dedupe_breakpoints(breakpoints),
    }


def _extract_python_file(rel: str, text: str, lines: list[str]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    reads: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    breakpoints: list[dict[str, Any]] = []
    tainted_vars: dict[str, dict[str, Any]] = {}

    def add_write(
        origin: dict[str, Any] | None,
        field: str,
        storage_kind: str,
        evidence: str,
        *,
        vulnerability_type: str = "xss",
        model: str | None = None,
    ) -> None:
        source = _origin_source(origin)
        if not source:
            return
        writes.append(
            _write_record(
                rel,
                line_no,
                "python",
                source,
                field,
                evidence,
                storage_kind=storage_kind,
                vulnerability_type=vulnerability_type,
                model=model,
                taint_trace=_origin_trace(origin),
            )
        )
        nodes.append(_storage_node(field, storage_kind, rel, line_no))
        edges.append(
            _edge(
                source["node_id"],
                _storage_id(field, storage_kind),
                "source_to_write",
                rel,
                line_no,
                evidence,
            )
        )

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        local_assign = PY_LOCAL_ASSIGN_RE.match(stripped)
        if local_assign:
            expr = local_assign.group("expr")
            origin = _origin_for_expr(
                expr,
                tainted_vars,
                rel,
                line_no,
                "python",
                expr,
                nodes,
            )
            if origin and not _looks_sanitized(expr):
                tainted_vars[local_assign.group("target")] = _extend_origin(
                    origin,
                    local_assign.group("target"),
                )

        field_match = PY_FIELD_ASSIGN_RE.match(stripped)
        if field_match and not _looks_sanitized(field_match.group("expr")):
            origin = _origin_for_expr(
                field_match.group("expr"),
                tainted_vars,
                rel,
                line_no,
                "python",
                field_match.group("expr"),
                nodes,
            )
            add_write(origin, field_match.group("field"), "orm_field", stripped)

        ctor_match = PY_CTOR_RE.search(stripped)
        if ctor_match:
            for kw in PY_KWARG_RE.finditer(ctor_match.group("args")):
                expr = kw.group("expr")
                if _looks_sanitized(expr):
                    continue
                origin = _origin_for_expr(
                    expr,
                    tainted_vars,
                    rel,
                    line_no,
                    "python",
                    expr,
                    nodes,
                )
                add_write(
                    origin,
                    kw.group("field"),
                    "orm_field",
                    stripped,
                    model=ctor_match.group("model"),
                )

        if SQL_INSERT_RE.search(stripped) or SQL_UPDATE_RE.search(stripped):
            origin = _origin_for_expr(
                stripped,
                tainted_vars,
                rel,
                line_no,
                "python",
                stripped,
                nodes,
            )
            if origin and not _looks_sanitized(stripped):
                for field in _sql_write_fields(stripped):
                    add_write(origin, field, "sql_field", stripped)

        if FILE_WRITE_RE.search(stripped):
            origin = _origin_for_expr(
                stripped,
                tainted_vars,
                rel,
                line_no,
                "python",
                stripped,
                nodes,
            )
            if origin and not _looks_sanitized(stripped):
                field = _field_from_expr(stripped) or "uploaded_file"
                add_write(
                    origin,
                    field,
                    "file_slot",
                    stripped,
                    vulnerability_type="file_operation",
                )

        if "render_template" in stripped:
            render = _line_window(lines, line_no, radius=8)
            reads.extend(_extract_render_reads(rel, line_no, render))

        if SQL_SELECT_RE.search(stripped):
            for field in _sql_select_fields(stripped):
                reads.append(
                    _read_record(
                        rel,
                        line_no,
                        "python",
                        field,
                        stripped,
                        storage_kind="sql_field",
                    )
                )

        if FILE_READ_RE.search(stripped):
            field = _field_from_expr(stripped) or "uploaded_file"
            sink = _sink_record(
                rel,
                line_no,
                "python",
                "file_operation",
                "file read/include sink",
                field,
                stripped,
                storage_kind="file_slot",
                severity="high",
            )
            sinks.append(sink)
            nodes.append(_storage_node(field, "file_slot", rel, line_no))
            nodes.append(_sink_node(sink))

    # Template literal sinks can appear in Python strings or inline Jinja.
    for sink in _extract_template_sinks(rel, lines, language="python"):
        sinks.append(sink)
        nodes.append(_sink_node(sink))
        nodes.append(_storage_node(sink["field"], "template_field", rel, sink["line"]))

    return {
        "nodes": nodes,
        "edges": edges,
        "writes": writes,
        "reads": reads,
        "sinks": sinks,
        "breakpoints": breakpoints,
    }


def _extract_php_file(rel: str, text: str, lines: list[str]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    reads: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    breakpoints: list[dict[str, Any]] = []
    tainted_vars: dict[str, dict[str, Any]] = {}

    def add_write(
        origin: dict[str, Any] | None,
        field: str,
        storage_kind: str,
        evidence: str,
        *,
        vulnerability_type: str = "xss",
    ) -> None:
        source = _origin_source(origin)
        if not source:
            return
        writes.append(
            _write_record(
                rel,
                line_no,
                "php",
                source,
                field,
                evidence,
                storage_kind=storage_kind,
                vulnerability_type=vulnerability_type,
                taint_trace=_origin_trace(origin),
            )
        )
        nodes.append(_storage_node(field, storage_kind, rel, line_no))
        edges.append(
            _edge(
                source["node_id"],
                _storage_id(field, storage_kind),
                "source_to_write",
                rel,
                line_no,
                evidence,
            )
        )

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue

        assign = PHP_ASSIGN_RE.match(stripped)
        if assign:
            expr = assign.group("expr")
            origin = _origin_for_expr(
                expr,
                tainted_vars,
                rel,
                line_no,
                "php",
                expr,
                nodes,
            )
            if origin and not _looks_sanitized(expr):
                tainted_vars[assign.group("var")] = _extend_origin(
                    origin,
                    assign.group("var"),
                )
                add_write(origin, assign.group("var"), "request_var", stripped)

        object_assign = PHP_OBJECT_ASSIGN_RE.match(stripped)
        if object_assign and not _looks_sanitized(object_assign.group("expr")):
            origin = _origin_for_expr(
                object_assign.group("expr"),
                tainted_vars,
                rel,
                line_no,
                "php",
                object_assign.group("expr"),
                nodes,
            )
            add_write(origin, object_assign.group("field"), "orm_field", stripped)

        array_assign = PHP_ARRAY_ASSIGN_RE.match(stripped)
        if array_assign and not _looks_sanitized(array_assign.group("expr")):
            origin = _origin_for_expr(
                array_assign.group("expr"),
                tainted_vars,
                rel,
                line_no,
                "php",
                array_assign.group("expr"),
                nodes,
            )
            add_write(origin, array_assign.group("field"), "orm_field", stripped)

        if SQL_INSERT_RE.search(stripped) or SQL_UPDATE_RE.search(stripped):
            origin = _origin_for_expr(
                stripped,
                tainted_vars,
                rel,
                line_no,
                "php",
                stripped,
                nodes,
            )
            if origin and not _looks_sanitized(stripped):
                for field in _sql_write_fields(stripped):
                    add_write(origin, field, "sql_field", stripped)

        if FILE_WRITE_RE.search(stripped):
            origin = _origin_for_expr(
                stripped,
                tainted_vars,
                rel,
                line_no,
                "php",
                stripped,
                nodes,
            )
            if origin and not _looks_sanitized(stripped):
                field = _php_source_fields(stripped) or [_field_from_expr(stripped) or "input"]
                add_write(
                    origin,
                    field[0],
                    "file_slot",
                    stripped,
                    vulnerability_type="file_operation",
                )

        if SQL_SELECT_RE.search(stripped):
            for field in _sql_select_fields(stripped):
                reads.append(
                    _read_record(rel, line_no, "php", field, stripped, storage_kind="sql_field")
                )

        echo_match = PHP_ECHO_RE.search(stripped)
        if echo_match and not _looks_sanitized(echo_match.group("expr")):
            field = _field_from_expr(echo_match.group("expr")) or "output"
            sink = _sink_record(
                rel,
                line_no,
                "php",
                "xss",
                "raw echo/print",
                field,
                stripped,
                storage_kind="template_field",
                severity="high",
            )
            sinks.append(sink)
            nodes.append(_sink_node(sink))

        if FILE_READ_RE.search(stripped):
            field = _field_from_expr(stripped) or "uploaded_file"
            sink = _sink_record(
                rel,
                line_no,
                "php",
                "file_inclusion" if "include" in stripped.lower() or "require" in stripped.lower() else "file_operation",
                "file read/include sink",
                field,
                stripped,
                storage_kind="file_slot",
                severity="critical" if "include" in stripped.lower() or "require" in stripped.lower() else "high",
            )
            sinks.append(sink)
            nodes.append(_storage_node(field, "file_slot", rel, line_no))
            nodes.append(_sink_node(sink))

    for sink in _extract_template_sinks(rel, lines, language="php"):
        sinks.append(sink)
        nodes.append(_sink_node(sink))

    return {
        "nodes": nodes,
        "edges": edges,
        "writes": writes,
        "reads": reads,
        "sinks": sinks,
        "breakpoints": breakpoints,
    }


def _extract_javascript_file(rel: str, text: str, lines: list[str]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    reads: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    breakpoints: list[dict[str, Any]] = []
    tainted_vars: dict[str, dict[str, Any]] = {}
    storage_var_bindings: dict[str, dict[str, str]] = {}

    def add_write(
        origin: dict[str, Any] | None,
        field: str,
        storage_kind: str,
        evidence: str,
        *,
        vulnerability_type: str = "xss",
    ) -> None:
        source = _origin_source(origin)
        if not source:
            return
        writes.append(
            _write_record(
                rel,
                line_no,
                "javascript",
                source,
                field,
                evidence,
                storage_kind=storage_kind,
                vulnerability_type=vulnerability_type,
                taint_trace=_origin_trace(origin),
            )
        )
        nodes.append(_storage_node(field, storage_kind, rel, line_no))
        edges.append(
            _edge(
                source["node_id"],
                _storage_id(field, storage_kind),
                "source_to_write",
                rel,
                line_no,
                evidence,
            )
        )

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        local_assign = JS_LOCAL_ASSIGN_RE.match(stripped)
        if local_assign:
            target = local_assign.group("target")
            expr = local_assign.group("expr")
            storage_get = JS_STORAGE_GET_RE.search(expr)
            if storage_get:
                key = _normalize_field(storage_get.group("key"))
                kind = "cache_key" if storage_get.group("store").lower() == "localstorage" else "session_key"
                storage_var_bindings[target] = {"field": key, "kind": kind}
                reads.append(
                    _read_record(
                        rel,
                        line_no,
                        "javascript",
                        key,
                        stripped,
                        storage_kind=kind,
                        expr=expr,
                    )
                )

            origin = _origin_for_expr(
                expr,
                tainted_vars,
                rel,
                line_no,
                "javascript",
                expr,
                nodes,
            )
            if origin and not _looks_sanitized(expr):
                tainted_vars[target] = _extend_origin(origin, target)
                add_write(origin, target, "request_var", stripped)

        prop_assign = JS_PROP_ASSIGN_RE.match(stripped)
        if prop_assign and not _looks_sanitized(prop_assign.group("expr")):
            origin = _origin_for_expr(
                prop_assign.group("expr"),
                tainted_vars,
                rel,
                line_no,
                "javascript",
                prop_assign.group("expr"),
                nodes,
            )
            add_write(origin, prop_assign.group("field"), "orm_field", stripped)

        storage_set = JS_STORAGE_SET_RE.search(stripped)
        if storage_set:
            expr = storage_set.group("expr")
            origin = _origin_for_expr(
                expr,
                tainted_vars,
                rel,
                line_no,
                "javascript",
                expr,
                nodes,
            )
            if origin and not _looks_sanitized(expr):
                kind = "cache_key" if storage_set.group("store").lower() == "localstorage" else "session_key"
                add_write(origin, storage_set.group("key"), kind, stripped)

        sink_match = JS_INNERHTML_RE.search(stripped)
        if sink_match and not _looks_sanitized(stripped):
            expr = (
                sink_match.group("expr")
                or sink_match.group("react")
                or sink_match.group("vue")
                or stripped
            )
            field = _field_from_expr(expr) or "html"
            storage_kind = "template_field"
            for var, binding in storage_var_bindings.items():
                if re.search(rf"\b{re.escape(var)}\b", expr):
                    field = binding["field"]
                    storage_kind = binding["kind"]
                    break
            sink = _sink_record(
                rel,
                line_no,
                "javascript",
                "xss",
                "raw html assignment",
                field,
                stripped,
                storage_kind=storage_kind,
                severity="high",
                expr=expr,
            )
            sinks.append(sink)
            nodes.append(_storage_node(field, storage_kind, rel, line_no))
            nodes.append(_sink_node(sink))

    return {
        "nodes": nodes,
        "edges": edges,
        "writes": writes,
        "reads": reads,
        "sinks": sinks,
        "breakpoints": breakpoints,
    }


def _extract_template_file(rel: str, lines: list[str]) -> dict[str, Any]:
    sinks = _extract_template_sinks(rel, lines, language="template")
    nodes = [_sink_node(sink) for sink in sinks]
    nodes.extend(_storage_node(sink["field"], "template_field", rel, sink["line"]) for sink in sinks)
    return {
        "nodes": nodes,
        "edges": [],
        "writes": [],
        "reads": [],
        "sinks": sinks,
        "breakpoints": [],
    }


def _extract_render_reads(rel: str, line_no: int, render_text: str) -> list[dict[str, Any]]:
    reads: list[dict[str, Any]] = []
    match = PY_RENDER_RE.search(render_text)
    if not match:
        return reads
    template_name = match.group("template")
    args = match.group("args") or ""
    for kw in PY_KWARG_RE.finditer(args):
        template_var = kw.group("field")
        expr = kw.group("expr").strip()
        field = _field_from_expr(expr) or template_var
        reads.append(
            _read_record(
                rel,
                line_no,
                "python",
                field,
                render_text.strip(),
                storage_kind="template_field",
                template=template_name,
                template_var=template_var,
                expr=expr,
            )
        )
    return reads


def _extract_template_sinks(rel: str, lines: list[str], *, language: str) -> list[dict[str, Any]]:
    sinks: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        for match in TEMPLATE_SAFE_RE.finditer(line):
            expr = match.group("expr").strip()
            field = _field_from_template_expr(expr)
            if not field:
                continue
            sinks.append(
                _sink_record(
                    rel,
                    line_no,
                    language,
                    "xss",
                    "template |safe/raw output",
                    field,
                    line.strip(),
                    storage_kind="template_field",
                    severity="high",
                    template=rel,
                    expr=expr,
                )
            )
    return sinks


def _origin_for_expr(
    expr: str,
    tainted_vars: dict[str, dict[str, Any]],
    rel: str,
    line_no: int,
    language: str,
    evidence: str,
    nodes: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return the request-origin for an expression and append direct source nodes.

    This deliberately stays local and cheap: it follows variables assigned from
    request data inside one file/function-sized scan pass, then uses that origin
    when the variable is written into DB fields, files, or templates.
    """
    expr = str(expr or "")
    source_re = SOURCE_PATTERNS.get(language)
    if source_re and source_re.search(expr):
        source = _source_node(rel, line_no, language, evidence or expr)
        nodes.append(source)
        return {"source": source, "trace": []}
    return _origin_from_tainted_vars(expr, tainted_vars)


def _origin_from_tainted_vars(
    expr: str,
    tainted_vars: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    expr = str(expr or "")
    for var in reversed(list(tainted_vars.keys())):
        if not var:
            continue
        if re.search(rf"\b{re.escape(var)}\b", expr):
            origin = tainted_vars[var]
            source = _origin_source(origin)
            if not source:
                continue
            return {
                "source": source,
                "trace": list(origin.get("trace") or []),
            }
    return None


def _extend_origin(origin: dict[str, Any], var_name: str) -> dict[str, Any]:
    trace = list(origin.get("trace") or [])
    normalized = _normalize_field(var_name)
    if normalized and (not trace or trace[-1] != normalized):
        trace.append(normalized)
    return {"source": _origin_source(origin), "trace": trace}


def _origin_source(origin: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(origin, dict):
        return None
    source = origin.get("source")
    return source if isinstance(source, dict) else None


def _origin_trace(origin: dict[str, Any] | None) -> list[str] | None:
    if not isinstance(origin, dict):
        return None
    trace = [str(item) for item in origin.get("trace") or [] if item]
    return trace or None


def _build_cross_request_chains(
    graph: dict[str, Any],
    callscan_chains: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    writes = graph.get("writes") or []
    reads = graph.get("reads") or []
    sinks = graph.get("sinks") or []

    chains: list[dict[str, Any]] = []
    seen: set[str] = set()

    for write in writes:
        write_keys = set(_storage_keys(write))
        for sink in sinks:
            if not _storage_keys_overlap(write_keys, set(_storage_keys(sink))):
                continue
            read = _best_read_for_sink(reads, sink, write_keys)
            chain = _chain_from_bridge(write, read, sink)
            if chain["chain_id"] in seen:
                continue
            seen.add(chain["chain_id"])
            chains.append(chain)

    # If CallScan already found high-severity no-context template/file sinks,
    # preserve them as recovery breakpoints for the auditor/UI to understand why
    # DataFlowScan did or did not bridge them.
    for item in callscan_chains:
        if not isinstance(item, dict):
            continue
        if item.get("has_call_chain"):
            continue
        vuln = str(item.get("vulnerability_type") or "")
        if vuln not in {"xss", "file_inclusion", "file_upload", "file_download", "file_path"}:
            continue
        sink_file = str(item.get("sink_file") or "")
        sink_line = int(item.get("sink_line") or 0)
        chain_id = "DF-R-" + _stable_hash(f"{item.get('chain_id')}:{sink_file}:{sink_line}")[:12]
        if chain_id in seen:
            continue
        seen.add(chain_id)
        chains.append(
            _recovered_partial_chain(
                item,
                chain_id=chain_id,
                sink_file=sink_file,
                sink_line=sink_line,
            )
        )

    chains = _dedupe_and_suppress_chains(chains)
    chains.sort(
        key=lambda c: (
            2 if c.get("chain_kind") == "cross_request" else 1,
            int(c.get("evidence_score") or 0),
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(c.get("severity") or ""), 0),
            str(c.get("sink_file") or ""),
            int(c.get("sink_line") or 0),
        ),
        reverse=True,
    )
    for idx, chain in enumerate(chains, start=1):
        chain["index"] = idx
    return chains


def _recovered_partial_chain(
    item: dict[str, Any],
    *,
    chain_id: str,
    sink_file: str,
    sink_line: int,
) -> dict[str, Any]:
    vuln = str(item.get("vulnerability_type") or "")
    sink_function = item.get("sink_function") or "sink"
    return {
                "type": "chain",
                "chain_kind": "recovered_partial",
                "chain_id": chain_id,
                "severity": item.get("severity") or "medium",
                "vulnerability_type": vuln or "unknown",
                "language": item.get("language") or "unknown",
                "sink_file": sink_file,
                "sink_line": sink_line,
                "sink_function": sink_function,
                "has_call_chain": False,
                "call_chain_count": 0,
                "call_chains": [],
                "evidence_quality": QUALITY_WEAK,
                "evidence_score": 15,
                "suppressed": True,
                "storage_identity": None,
                "binding_edges": [],
                "sanitizer_trace": _sanitizer_trace(item.get("audit_pack") or item.get("summary") or "", vuln),
                "positive_evidence": [],
                "refuting_evidence": [],
                "weak_sanitizer": [],
                "noise_tags": ["missing_storage_bridge", "weak_recovered_partial"],
                "summary": "CallScan found a high-risk sink, but DataFlowScan could not recover a storage bridge.",
                "breakpoints": ["missing_storage_bridge"],
                "recovery_trace": [
                    {
                        "kind": "callscan_sink_without_storage_bridge",
                        "chain_id": item.get("chain_id"),
                        "sink_file": sink_file,
                        "sink_line": sink_line,
                    }
                ],
                "audit_pack": _partial_audit_pack(item),
            }


def _chain_from_bridge(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
) -> dict[str, Any]:
    storage = write["storage"]
    storage_identity = _best_storage_identity(write, read, sink)
    binding_edges = _merge_binding_edges(write, read, sink)
    sanitizer_trace = _merge_sanitizer_trace(write, read, sink)
    positive_evidence = _merge_positive_evidence(write, read, sink)
    refuting_evidence = _refuting_evidence(
        sanitizer_trace,
        sink.get("vulnerability_type") or write.get("vulnerability_type") or "unknown",
    )
    weak_sanitizer = [item for item in sanitizer_trace if item.get("strength") == "weak"]
    match_quality = _storage_match_quality(write, read, sink)
    breakpoints = _chain_breakpoints(write, read, sink, match_quality)
    noise_tags = _chain_noise_tags(write, read, sink, match_quality, refuting_evidence)
    evidence_score, evidence_quality = _score_chain(
        write=write,
        read=read,
        sink=sink,
        match_quality=match_quality,
        breakpoints=breakpoints,
        sanitizer_trace=sanitizer_trace,
        positive_evidence=positive_evidence,
        refuting_evidence=refuting_evidence,
        noise_tags=noise_tags,
    )
    chain_id = "DF-" + _stable_hash(
        f"{write['file']}:{write['line']}:{storage['key']}:{sink['file']}:{sink['line']}"
    )[:12]
    severity = sink.get("severity") or ("critical" if sink.get("vulnerability_type") == "file_inclusion" else "high")
    nodes = [
        {
            "role": "source",
            "file": write["file"],
            "line": write["line"],
            "function": write.get("handler") or "<request handler>",
            "expr": write.get("source", {}).get("expr"),
        },
        {
            "role": "storage",
            "file": write["file"],
            "line": write["line"],
            "function": storage.get("label"),
            "expr": storage.get("key"),
        },
    ]
    if read:
        nodes.append(
            {
                "role": "read",
                "file": read["file"],
                "line": read["line"],
                "function": read.get("template_var") or "<read request>",
                "expr": read.get("expr") or read.get("evidence"),
            }
        )
    nodes.append(
        {
            "role": "sink",
            "file": sink["file"],
            "line": sink["line"],
            "function": sink.get("sink_function") or "sink",
            "expr": sink.get("evidence"),
        }
    )
    return {
        "type": "chain",
        "chain_kind": "cross_request",
        "chain_id": chain_id,
        "severity": severity,
        "vulnerability_type": sink.get("vulnerability_type") or write.get("vulnerability_type") or "unknown",
        "language": sink.get("language") if sink.get("language") != "template" else write.get("language"),
        "sink_file": sink["file"],
        "sink_line": sink["line"],
        "sink_function": sink.get("sink_function") or "sink",
        "has_call_chain": True,
        "call_chain_count": 1,
        "call_chains": [nodes],
        "source": write.get("source"),
        "storage": storage,
        "storage_identity": storage_identity,
        "storage_edges": [
            {
                "kind": "write_to_storage",
                "file": write["file"],
                "line": write["line"],
                "storage_key": storage["key"],
                "evidence": write.get("evidence"),
            },
            {
                "kind": "storage_to_sink" if read is None else "storage_to_read",
                "file": (read or sink)["file"],
                "line": (read or sink)["line"],
                "storage_key": storage["key"],
                "evidence": (read or sink).get("evidence"),
            },
        ],
        "binding_edges": binding_edges,
        "sanitizer_trace": sanitizer_trace,
        "positive_evidence": positive_evidence,
        "refuting_evidence": refuting_evidence,
        "weak_sanitizer": weak_sanitizer,
        "evidence_quality": evidence_quality,
        "evidence_score": evidence_score,
        "suppressed": evidence_quality == QUALITY_WEAK or "sanitized_before_sink" in noise_tags,
        "noise_tags": noise_tags,
        "dataflow_nodes": nodes,
        "breakpoints": breakpoints,
        "recovery_trace": [
            {
                "kind": "source_to_storage",
                "file": write["file"],
                "line": write["line"],
                "field": storage.get("field"),
            },
            {
                "kind": "storage_to_sink",
                "file": sink["file"],
                "line": sink["line"],
                "field": sink.get("field"),
                "via_template_binding": bool(read),
                "match_quality": match_quality,
            },
        ],
        "summary": _chain_summary(write, read, sink),
        "audit_pack": _cross_request_audit_pack(
            write,
            read,
            sink,
            nodes,
            evidence_quality=evidence_quality,
            evidence_score=evidence_score,
            storage_identity=storage_identity,
            breakpoints=breakpoints,
            sanitizer_trace=sanitizer_trace,
            refuting_evidence=refuting_evidence,
            noise_tags=noise_tags,
        ),
    }


def _chain_summary(write: dict[str, Any], read: dict[str, Any] | None, sink: dict[str, Any]) -> str:
    storage = write["storage"]
    return (
        f"Cross-request flow: attacker-controlled input at {write['file']}:{write['line']} "
        f"writes {storage['label']}; "
        f"{'read at ' + read['file'] + ':' + str(read['line']) + ' then ' if read else ''}"
        f"reaches {sink.get('sink_function') or 'sink'} at {sink['file']}:{sink['line']}."
    )


def _cross_request_audit_pack(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
    nodes: list[dict[str, Any]],
    *,
    evidence_quality: str,
    evidence_score: int,
    storage_identity: dict[str, Any] | None,
    breakpoints: list[str],
    sanitizer_trace: list[dict[str, Any]],
    refuting_evidence: list[dict[str, Any]],
    noise_tags: list[str],
) -> str:
    storage = write["storage"]
    lines = [
        "# DataFlowScan cross-request candidate",
        "",
        f"chain_kind: cross_request",
        f"vulnerability_type: {sink.get('vulnerability_type') or 'unknown'}",
        f"evidence_quality: {evidence_quality}",
        f"evidence_score: {evidence_score}",
        f"storage_bridge: {storage['label']} ({storage['key']})",
    ]
    if storage_identity:
        lines.append(f"storage_identity: {storage_identity.get('identity') or storage_identity}")
    if breakpoints:
        lines.append(f"breakpoints: {', '.join(breakpoints)}")
    if noise_tags:
        lines.append(f"noise_tags: {', '.join(noise_tags)}")
    lines.extend(
        [
            "",
            "## Required audit questions",
            "- Is the write request attacker-controlled?",
            "- Does the storage bridge identify the same DB field/file/cache key?",
            "- Is the read/render request reachable by an attacker or victim?",
            "- Is the sink dangerous, and is escaping/sanitization missing?",
            "- If verdict is uncertain, map missing_info to the listed breakpoints.",
            "",
            "## Data flow",
        ]
    )
    for idx, node in enumerate(nodes, start=1):
        lines.append(
            f"{idx}. {node['role']}: {node.get('file')}:{node.get('line')} "
            f"{node.get('function') or ''} {node.get('expr') or ''}".strip()
        )
    lines.extend(
        [
            "",
            "## Evidence",
            f"- write: {write['file']}:{write['line']} `{_trim(write.get('evidence'))}`",
        ]
    )
    if write.get("taint_trace"):
        lines.append(f"- local_taint: {' -> '.join(write.get('taint_trace') or [])}")
    if read:
        lines.append(f"- read: {read['file']}:{read['line']} `{_trim(read.get('evidence'))}`")
    lines.append(f"- sink: {sink['file']}:{sink['line']} `{_trim(sink.get('evidence'))}`")
    if sanitizer_trace:
        lines.append("")
        lines.append("## Sanitizer/refutation trace")
        for item in sanitizer_trace[:8]:
            lines.append(
                f"- {item.get('kind')}:{item.get('strength')} "
                f"{item.get('file')}:{item.get('line')} `{_trim(item.get('evidence'))}`"
            )
    if refuting_evidence:
        lines.append("")
        lines.append("## Refuting evidence")
        for item in refuting_evidence[:6]:
            lines.append(f"- {item.get('kind')}: {_trim(item.get('evidence'))}")
    return "\n".join(lines).rstrip() + "\n"


def _partial_audit_pack(item: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# DataFlowScan recovered partial candidate",
            "",
            "chain_kind: recovered_partial",
            "breakpoints: missing_storage_bridge",
            "",
            "CallScan evidence:",
            item.get("audit_pack") or item.get("summary") or "(no audit pack)",
        ]
    ).rstrip() + "\n"


def _write_cross_request_jsonl(
    path: Path,
    chains: list[dict[str, Any]],
    *,
    project_path: str,
    scope: RunScope,
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fp:
        fp.write(
            json.dumps(
                {
                    "type": "meta",
                    "schema_version": "defectmine.dataflowscan.cross_request_chain.v2",
                    "project_path": project_path,
                    "mode": scope.mode,
                    "run_id": scope.run_id,
                    "target_rel_dir": scope.target_rel_dir,
                    "total_chains": len(chains),
                    "schema": [
                        "chain_id",
                        "chain_kind",
                        "severity",
                        "vulnerability_type",
                        "language",
                        "sink_file",
                        "sink_line",
                        "evidence_quality",
                        "evidence_score",
                        "storage_identity",
                        "binding_edges",
                        "sanitizer_trace",
                        "positive_evidence",
                        "refuting_evidence",
                        "weak_sanitizer",
                        "noise_tags",
                        "suppressed",
                        "storage_edges",
                        "breakpoints",
                        "audit_pack",
                    ],
                },
                ensure_ascii=False,
            )
            + "\n"
        )
        for chain in chains:
            fp.write(json.dumps(chain, ensure_ascii=False) + "\n")
    return len(chains)


def _build_summary(
    graph: dict[str, Any],
    chains: list[dict[str, Any]],
    started_at: float,
) -> dict[str, Any]:
    node_counts = Counter(node.get("kind") for node in graph.get("nodes") or [])
    edge_counts = Counter(edge.get("kind") for edge in graph.get("edges") or [])
    vuln_counts = Counter(chain.get("vulnerability_type") or "unknown" for chain in chains)
    chain_kind_counts = Counter(chain.get("chain_kind") or "unknown" for chain in chains)
    quality_counts = Counter(chain.get("evidence_quality") or "legacy" for chain in chains)
    noise_counts: Counter[str] = Counter()
    breakpoint_counts: Counter[str] = Counter()
    for chain in chains:
        noise_counts.update(str(tag) for tag in chain.get("noise_tags") or [] if tag)
        breakpoint_counts.update(str(bp) for bp in chain.get("breakpoints") or [] if bp)
    total_chains = len(chains)
    cross_request_chains = chain_kind_counts.get("cross_request", 0)
    recovered_partial = chain_kind_counts.get("recovered_partial", 0)
    suppressed_chains = sum(1 for chain in chains if chain.get("suppressed"))
    deduplicated_chains = noise_counts.get("duplicate_storage_sink", 0)
    storage_counts = Counter(
        (write.get("storage") or {}).get("kind") or "unknown"
        for write in graph.get("writes") or []
    )
    return {
        "nodes": len(graph.get("nodes") or []),
        "edges": len(graph.get("edges") or []),
        "source_nodes": node_counts.get(SOURCE_NODE, 0),
        "storage_nodes": node_counts.get(STORAGE_NODE, 0),
        "sink_nodes": node_counts.get(SINK_NODE, 0),
        "write_edges": edge_counts.get("source_to_write", 0),
        "read_edges": len(graph.get("reads") or []),
        "total_chains": total_chains,
        "cross_request_chains": cross_request_chains,
        "recovered_partial": recovered_partial,
        "confirmed_chains": quality_counts.get(QUALITY_CONFIRMED, 0),
        "probable_chains": quality_counts.get(QUALITY_PROBABLE, 0),
        "weak_chains": quality_counts.get(QUALITY_WEAK, 0),
        "suppressed_chains": suppressed_chains,
        "deduplicated_chains": deduplicated_chains,
        "by_vulnerability": dict(vuln_counts),
        "by_chain_kind": dict(chain_kind_counts),
        "by_evidence_quality": dict(quality_counts),
        "by_storage_kind": dict(storage_counts),
        "by_noise_tag": dict(noise_counts),
        "by_breakpoint": dict(breakpoint_counts),
        "breakpoints": len(graph.get("breakpoints") or []),
        "elapsed_seconds": round(time.perf_counter() - started_at, 2),
    }


def _iter_source_files(project_root: Path, scope: RunScope) -> list[Path]:
    paths: list[Path] = []
    root = scope.target_abs_dir if scope.mode == "specific" and scope.target_abs_dir else project_root
    if not root.is_dir():
        return paths
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        rel = _rel_path(project_root, path)
        if not scope.contains_rel_path(rel):
            continue
        skip, _ = should_skip_for_scan(rel)
        if skip or ".defectmine/" in rel or rel.startswith(".defectmine/"):
            continue
        paths.append(path)
    return paths


def _language_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".php", ".phtml"}:
        return "php"
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "javascript"
    return "template"


def _source_node(rel: str, line: int, language: str, evidence: str) -> dict[str, Any]:
    node_id = _node_id(SOURCE_NODE, rel, line, evidence)
    return {
        "node_id": node_id,
        "kind": SOURCE_NODE,
        "language": language,
        "file": rel,
        "line": line,
        "label": "request input",
        "expr": _trim(evidence),
    }


def _storage_node(field: str, kind: str, rel: str, line: int) -> dict[str, Any]:
    storage_id = _storage_id(field, kind)
    return {
        "node_id": storage_id,
        "kind": STORAGE_NODE,
        "storage_kind": kind,
        "file": rel,
        "line": line,
        "label": _storage_label(field, kind),
        "field": field,
        "key": _field_key(field),
    }


def _sink_node(sink: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_id": sink["node_id"],
        "kind": SINK_NODE,
        "language": sink.get("language"),
        "file": sink.get("file"),
        "line": sink.get("line"),
        "label": sink.get("sink_function"),
        "vulnerability_type": sink.get("vulnerability_type"),
        "field": sink.get("field"),
        "expr": _trim(sink.get("evidence")),
    }


def _write_record(
    rel: str,
    line: int,
    language: str,
    source: dict[str, Any],
    field: str,
    evidence: str,
    *,
    storage_kind: str,
    vulnerability_type: str = "xss",
    model: str | None = None,
    taint_trace: list[str] | None = None,
) -> dict[str, Any]:
    field = _normalize_field(field)
    storage = {
        "kind": storage_kind,
        "field": field,
        "key": _field_key(field),
        "storage_id": _storage_id(field, storage_kind),
        "label": _storage_label(field, storage_kind, model=model),
    }
    storage_identity = _storage_identity(storage, evidence)
    record = {
        "file": rel,
        "line": line,
        "language": language,
        "source": source,
        "storage": storage,
        "storage_identity": storage_identity,
        "binding_edges": [
            _binding_edge(
                "source_to_storage",
                rel,
                line,
                source.get("expr") or source.get("label") or "request",
                storage_identity.get("identity") or storage["key"],
                evidence,
                confidence="confirmed" if storage_kind not in {"request_var"} else "probable",
            )
        ],
        "sanitizer_trace": _sanitizer_trace(evidence, vulnerability_type),
        "handler": "<request handler>",
        "vulnerability_type": vulnerability_type,
        "evidence": _trim(evidence),
        "confidence": "medium" if storage_kind in {"request_var", "file_slot"} else "high",
    }
    if taint_trace:
        record["taint_trace"] = taint_trace
    return record


def _read_record(
    rel: str,
    line: int,
    language: str,
    field: str,
    evidence: str,
    *,
    storage_kind: str,
    template: str | None = None,
    template_var: str | None = None,
    expr: str | None = None,
) -> dict[str, Any]:
    field = _normalize_field(field)
    storage = {
        "kind": storage_kind,
        "field": field,
        "key": _field_key(field),
        "storage_id": _storage_id(field, storage_kind),
        "label": _storage_label(field, storage_kind),
    }
    storage_identity = _storage_identity(storage, evidence)
    source_expr = expr or field
    return {
        "file": rel,
        "line": line,
        "language": language,
        "field": field,
        "storage": storage,
        "storage_identity": storage_identity,
        "binding_edges": [
            _binding_edge(
                "storage_to_read",
                rel,
                line,
                storage_identity.get("identity") or storage["key"],
                template_var or source_expr,
                evidence,
                confidence="confirmed" if template_var or storage_kind == "sql_field" else "probable",
            )
        ],
        "sanitizer_trace": _sanitizer_trace(evidence, "xss"),
        "template": template,
        "template_var": template_var,
        "expr": expr,
        "evidence": _trim(evidence),
        "confidence": "medium",
    }


def _sink_record(
    rel: str,
    line: int,
    language: str,
    vulnerability_type: str,
    sink_function: str,
    field: str,
    evidence: str,
    *,
    storage_kind: str,
    severity: str,
    template: str | None = None,
    expr: str | None = None,
) -> dict[str, Any]:
    field = _normalize_field(field)
    node_id = _node_id(SINK_NODE, rel, line, evidence)
    storage = {
        "kind": storage_kind,
        "field": field,
        "key": _field_key(field),
        "storage_id": _storage_id(field, storage_kind),
        "label": _storage_label(field, storage_kind),
    }
    storage_identity = _storage_identity(storage, evidence)
    return {
        "node_id": node_id,
        "file": rel,
        "line": line,
        "language": language,
        "vulnerability_type": vulnerability_type,
        "sink_function": sink_function,
        "field": field,
        "storage": storage,
        "storage_identity": storage_identity,
        "binding_edges": [
            _binding_edge(
                "read_to_sink",
                rel,
                line,
                expr or field,
                sink_function,
                evidence,
                confidence="confirmed" if _positive_sink_evidence(vulnerability_type, evidence) else "probable",
            )
        ],
        "sanitizer_trace": _sanitizer_trace(evidence, vulnerability_type),
        "positive_evidence": _positive_evidence(vulnerability_type, evidence, storage_kind),
        "template": template,
        "expr": expr,
        "severity": severity,
        "evidence": _trim(evidence),
        "confidence": "medium" if storage_kind == "file_slot" else "high",
    }


def _edge(
    from_id: str,
    to_id: str,
    kind: str,
    rel: str,
    line: int,
    evidence: str,
) -> dict[str, Any]:
    return {
        "edge_id": _stable_hash(f"{kind}:{from_id}:{to_id}:{rel}:{line}")[:16],
        "from": from_id,
        "to": to_id,
        "kind": kind,
        "file": rel,
        "line": line,
        "evidence": _trim(evidence),
        "confidence": "medium",
    }


def _storage_keys(record: dict[str, Any]) -> list[str]:
    storage = record.get("storage") if isinstance(record.get("storage"), dict) else {}
    field = _normalize_field(storage.get("field") or record.get("field") or "")
    keys = {_field_key(field)} if field else set()
    kind = storage.get("kind")
    if field and kind:
        keys.add(f"{kind}:{field}")
    return sorted(keys)


def _storage_identity(
    storage: dict[str, Any],
    evidence: str | None = None,
) -> dict[str, Any]:
    kind = str(storage.get("kind") or "unknown")
    field = _normalize_field(storage.get("field") or "")
    sql_meta = _sql_identity_from_text(evidence or "", field)
    if kind == "sql_field":
        table = sql_meta.get("table")
        column = sql_meta.get("column") or field
        identity = f"sql_column:{table or '*'}:{column or '*'}"
        confidence = "confirmed" if table and column else "probable" if column else "weak"
        return {
            "kind": "sql_column",
            "database": None,
            "table": table,
            "column": column,
            "alias": sql_meta.get("alias"),
            "identity": identity,
            "confidence": confidence,
        }
    if kind == "file_slot":
        path_expr = _file_path_expr(evidence or "")
        identity = f"file_path:{path_expr or field or '*'}"
        return {
            "kind": "file_path",
            "path": path_expr,
            "field": field,
            "identity": identity,
            "confidence": "confirmed" if path_expr else "probable" if field else "weak",
        }
    if kind == "request_var":
        return {
            "kind": "request_var",
            "name": field,
            "identity": f"request_var:{field or '*'}",
            "confidence": "probable" if field else "weak",
        }
    if kind in {"session_key", "cache_key", "config_key"}:
        return {
            "kind": kind,
            "key": field,
            "identity": f"{kind}:{field or '*'}",
            "confidence": "confirmed" if field else "weak",
        }
    if kind == "template_field":
        return {
            "kind": "template_binding",
            "symbol": field,
            "identity": f"template_binding:{field or '*'}",
            "confidence": "probable" if field else "weak",
        }
    return {
        "kind": kind,
        "field": field,
        "identity": f"{kind}:{field or '*'}",
        "confidence": "probable" if field else "weak",
    }


def _sql_identity_from_text(text: str, field: str) -> dict[str, Any]:
    insert = SQL_INSERT_RE.search(text or "")
    if insert:
        columns = _split_sql_columns(insert.group("columns"))
        column = field if field in columns else (columns[0] if columns else field)
        return {"table": _normalize_field(insert.group("table")), "column": column}
    update = SQL_UPDATE_RE.search(text or "")
    if update:
        columns = _sql_write_fields(text)
        column = field if field in columns else (columns[0] if columns else field)
        return {"table": _normalize_field(update.group("table")), "column": column}
    select = SQL_SELECT_RE.search(text or "")
    if select:
        raw_columns = select.group("columns")
        columns = _split_sql_columns(raw_columns) if "*" not in raw_columns else []
        column = field if field in columns else field
        return {"table": _normalize_field(select.group("table")), "column": column}
    return {"table": None, "column": field}


def _file_path_expr(text: str) -> str | None:
    text = _trim(text)
    if not text:
        return None
    match = re.search(r"(?:save|move_uploaded_file|file_put_contents|open|writeFile)\s*\((?P<args>[^)]{1,240})", text, re.IGNORECASE)
    if not match:
        return None
    args = match.group("args")
    first = args.split(",", 1)[0].strip()
    if first:
        return _trim(first, limit=120)
    return None


def _binding_edge(
    kind: str,
    file: str,
    line: int,
    source_symbol: Any,
    target_symbol: Any,
    evidence: Any,
    *,
    confidence: str,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "file": file,
        "line": line,
        "source_symbol": str(source_symbol or ""),
        "target_symbol": str(target_symbol or ""),
        "evidence": _trim(evidence),
        "confidence": confidence,
    }


def _sanitizer_trace(text: Any, vulnerability_type: str) -> list[dict[str, Any]]:
    evidence = str(text or "")
    if not evidence:
        return []
    trace: list[dict[str, Any]] = []
    if STRONG_SANITIZER_RE.search(evidence):
        trace.append(
            {
                "kind": _sanitizer_kind(vulnerability_type),
                "strength": "strong",
                "evidence": _trim(evidence),
            }
        )
    if WEAK_SANITIZER_RE.search(evidence):
        trace.append(
            {
                "kind": _sanitizer_kind(vulnerability_type),
                "strength": "weak",
                "evidence": _trim(evidence),
            }
        )
    return trace


def _sanitizer_kind(vulnerability_type: str) -> str:
    vuln = str(vulnerability_type or "")
    if vuln == "xss":
        return "html_escape"
    if vuln in {"sql_injection", "sqli"}:
        return "parameterized_query"
    if vuln.startswith("file") or vuln == "file_operation":
        return "path_or_filename_policy"
    if vuln in {"rce", "code_execution", "deserialization"}:
        return "execution_guard"
    if vuln == "ssrf":
        return "url_allowlist"
    return "sanitizer"


def _positive_evidence(vulnerability_type: str, evidence: Any, storage_kind: str) -> list[dict[str, Any]]:
    text = str(evidence or "")
    out: list[dict[str, Any]] = []
    if _positive_sink_evidence(vulnerability_type, text):
        out.append({"kind": "dangerous_sink", "evidence": _trim(text)})
    if storage_kind == "file_slot":
        out.append(_file_flow_evidence(text))
    return [item for item in out if item]


def _positive_sink_evidence(vulnerability_type: str, evidence: str) -> bool:
    vuln = str(vulnerability_type or "")
    if vuln == "xss":
        return bool(RAW_XSS_SINK_RE.search(evidence or ""))
    if vuln.startswith("file") or vuln == "file_operation":
        return bool(FILE_READ_RE.search(evidence or "") or FILE_WRITE_RE.search(evidence or ""))
    return True


def _file_flow_evidence(text: str) -> dict[str, Any]:
    return {
        "kind": "file_flow",
        "source": "multipart file" if FILE_UPLOAD_SOURCE_RE.search(text or "") else "unknown",
        "filename_expr": "original filename" if "filename" in (text or "").lower() else "unknown",
        "save_call": _trim(text),
        "save_path": _file_path_expr(text or "") or "unknown",
        "web_accessible": bool(WEB_ACCESSIBLE_PATH_RE.search(text or "")),
        "filename_sanitizer": "present" if FILE_NAME_SANITIZER_RE.search(text or "") else "missing",
        "extension_policy": "present" if EXTENSION_POLICY_RE.search(text or "") else "unknown",
        "confidence": "confirmed" if FILE_WRITE_RE.search(text or "") else "weak",
    }


def _best_storage_identity(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
) -> dict[str, Any] | None:
    identities = [
        item
        for item in (
            write.get("storage_identity"),
            read.get("storage_identity") if read else None,
            sink.get("storage_identity"),
        )
        if isinstance(item, dict)
    ]
    if not identities:
        return None
    identities.sort(
        key=lambda item: {"confirmed": 3, "probable": 2, "weak": 1}.get(str(item.get("confidence") or ""), 0),
        reverse=True,
    )
    return identities[0]


def _merge_binding_edges(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for record in (write, read, sink):
        if not isinstance(record, dict):
            continue
        for edge in record.get("binding_edges") or []:
            if isinstance(edge, dict):
                edges.append(edge)
    return _dedupe_dicts(edges, ("kind", "file", "line", "source_symbol", "target_symbol"))


def _merge_sanitizer_trace(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    for record in (write, read, sink):
        if not isinstance(record, dict):
            continue
        for item in record.get("sanitizer_trace") or []:
            if isinstance(item, dict):
                trace.append({**item, "file": record.get("file"), "line": record.get("line")})
    return _dedupe_dicts(trace, ("kind", "strength", "file", "line", "evidence"))


def _merge_positive_evidence(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for record in (write, read, sink):
        if not isinstance(record, dict):
            continue
        for item in record.get("positive_evidence") or []:
            if isinstance(item, dict):
                evidence.append({**item, "file": record.get("file"), "line": record.get("line")})
    if read and read.get("template_var"):
        evidence.append(
            {
                "kind": "template_binding",
                "template": read.get("template"),
                "sink_expr": sink.get("expr") or sink.get("evidence"),
                "bound_symbol": read.get("template_var"),
                "source_symbol": read.get("expr") or read.get("field"),
                "confidence": "confirmed",
                "file": read.get("file"),
                "line": read.get("line"),
            }
        )
    return _dedupe_dicts(evidence, ("kind", "file", "line", "evidence", "bound_symbol"))


def _refuting_evidence(
    sanitizer_trace: list[dict[str, Any]],
    vulnerability_type: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in sanitizer_trace:
        if item.get("strength") != "strong":
            continue
        out.append(
            {
                "kind": item.get("kind") or _sanitizer_kind(vulnerability_type),
                "file": item.get("file"),
                "line": item.get("line"),
                "evidence": item.get("evidence"),
            }
        )
    return out


def _storage_match_quality(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
) -> str:
    write_keys = set(_storage_keys(write))
    sink_keys = set(_storage_keys(sink))
    read_keys = set(_storage_keys(read or {}))
    write_typed = _typed_storage_keys(write)
    sink_typed = _typed_storage_keys(sink)
    read_typed = _typed_storage_keys(read or {})
    if write_typed & sink_typed or (read and write_typed & read_typed and sink_typed & read_typed):
        return "exact_storage_key"
    write_fields = {item.split(":", 1)[-1] for item in write_keys}
    sink_fields = {item.split(":", 1)[-1] for item in sink_keys}
    read_fields = {item.split(":", 1)[-1] for item in read_keys}
    if read and write_fields & read_fields and sink_fields & read_fields:
        return "template_binding" if read.get("template_var") else "storage_read_binding"
    if write_fields & sink_fields:
        return "weak_name_match"
    return "no_match"


def _typed_storage_keys(record: dict[str, Any]) -> set[str]:
    return {key for key in _storage_keys(record) if ":" in key and not key.startswith("field:")}


def _chain_breakpoints(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
    match_quality: str,
) -> list[str]:
    breakpoints: list[str] = []
    storage_kind = ((write.get("storage") or {}).get("kind") or "")
    if match_quality == "weak_name_match":
        if storage_kind == "sql_field":
            breakpoints.append("missing_sql_column_mapping")
        elif storage_kind == "file_slot":
            breakpoints.append("missing_file_save_path")
        else:
            breakpoints.append("weak_storage_name_match")
    if match_quality == "storage_read_binding":
        breakpoints.append("missing_template_binding")
    if not read and (sink.get("storage") or {}).get("kind") == "template_field":
        breakpoints.append("missing_template_binding")
    if storage_kind == "file_slot":
        file_ev = " ".join(str(item.get("evidence") or "") for item in write.get("positive_evidence") or [])
        if not FILE_WRITE_RE.search(str(write.get("evidence") or "") + file_ev):
            breakpoints.append("missing_file_save_path")
    return sorted(set(bp for bp in breakpoints if bp))


def _chain_noise_tags(
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
    match_quality: str,
    refuting_evidence: list[dict[str, Any]],
) -> list[str]:
    tags: list[str] = []
    if match_quality == "weak_name_match":
        tags.append("weak_name_match")
    if match_quality == "storage_read_binding":
        tags.append("storage_read_without_template_binding")
    if not read and (sink.get("storage") or {}).get("kind") == "template_field":
        tags.append("missing_template_binding")
    if refuting_evidence:
        tags.append("sanitized_before_sink")
    return sorted(set(tags))


def _score_chain(
    *,
    write: dict[str, Any],
    read: dict[str, Any] | None,
    sink: dict[str, Any],
    match_quality: str,
    breakpoints: list[str],
    sanitizer_trace: list[dict[str, Any]],
    positive_evidence: list[dict[str, Any]],
    refuting_evidence: list[dict[str, Any]],
    noise_tags: list[str],
) -> tuple[int, str]:
    score = 25
    if write.get("source"):
        score += 15
    if match_quality == "exact_storage_key":
        score += 25
    elif match_quality == "template_binding":
        score += 25
    elif match_quality == "storage_read_binding":
        score += 15
    elif match_quality == "weak_name_match":
        score += 8
    if read:
        score += 20
    if sink.get("sink_function"):
        score += 10
    if positive_evidence:
        score += min(15, 5 * len(positive_evidence))
    if refuting_evidence:
        score -= 35
    if breakpoints:
        score -= min(30, 12 * len(breakpoints))
    if "weak_name_match" in noise_tags:
        score -= 15
    if any(item.get("strength") == "weak" for item in sanitizer_trace):
        score -= 5
    score = max(0, min(100, score))
    if (
        score >= 80
        and read
        and not refuting_evidence
        and match_quality in {"exact_storage_key", "template_binding"}
    ):
        quality = QUALITY_CONFIRMED
    elif score >= 50 and not refuting_evidence:
        quality = QUALITY_PROBABLE
    else:
        quality = QUALITY_WEAK
    return score, quality


def _dedupe_and_suppress_chains(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best_by_key: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    output: list[dict[str, Any]] = []
    for chain in chains:
        storage_identity = chain.get("storage_identity") if isinstance(chain.get("storage_identity"), dict) else {}
        identity = str(storage_identity.get("identity") or (chain.get("storage") or {}).get("key") or "")
        key = (
            identity,
            str(chain.get("sink_file") or ""),
            int(chain.get("sink_line") or 0),
            str(chain.get("vulnerability_type") or ""),
        )
        if not identity:
            output.append(chain)
            continue
        current = best_by_key.get(key)
        if current is None:
            best_by_key[key] = chain
            output.append(chain)
            continue
        keep, drop = (
            (chain, current)
            if int(chain.get("evidence_score") or 0) > int(current.get("evidence_score") or 0)
            else (current, chain)
        )
        drop["suppressed"] = True
        drop.setdefault("noise_tags", [])
        if "duplicate_storage_sink" not in drop["noise_tags"]:
            drop["noise_tags"].append("duplicate_storage_sink")
        if keep is chain:
            best_by_key[key] = chain
        output.append(chain)
    return output


def _dedupe_dicts(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = tuple(item.get(name) for name in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _storage_keys_overlap(left: set[str], right: set[str]) -> bool:
    if left & right:
        return True
    left_fields = {item.split(":", 1)[-1] for item in left}
    right_fields = {item.split(":", 1)[-1] for item in right}
    return bool(left_fields & right_fields)


def _best_read_for_sink(
    reads: list[dict[str, Any]],
    sink: dict[str, Any],
    write_keys: set[str],
) -> dict[str, Any] | None:
    sink_keys = set(_storage_keys(sink))
    candidates = [
        read
        for read in reads
        if _storage_keys_overlap(write_keys, set(_storage_keys(read)))
        or _storage_keys_overlap(sink_keys, set(_storage_keys(read)))
    ]
    if not candidates:
        return None
    sink_template = str(sink.get("template") or "")
    candidates.sort(
        key=lambda read: (
            1 if sink_template and sink_template.endswith(str(read.get("template") or "")) else 0,
            1 if read.get("template_var") == sink.get("field") else 0,
            -abs(int(read.get("line") or 0) - int(sink.get("line") or 0)),
        ),
        reverse=True,
    )
    return candidates[0]


def _sql_write_fields(text: str) -> list[str]:
    fields: list[str] = []
    match = SQL_INSERT_RE.search(text)
    if match:
        fields.extend(_split_sql_columns(match.group("columns")))
    update = SQL_UPDATE_RE.search(text)
    if update:
        for part in update.group("sets").split(","):
            left = part.split("=", 1)[0].strip(" `\"'")
            if left:
                fields.append(left)
    return [_normalize_field(field) for field in fields if _normalize_field(field)]


def _sql_select_fields(text: str) -> list[str]:
    match = SQL_SELECT_RE.search(text)
    if not match:
        return []
    raw = match.group("columns")
    if "*" in raw:
        return []
    return [_normalize_field(field) for field in _split_sql_columns(raw) if _normalize_field(field)]


def _split_sql_columns(raw: str) -> list[str]:
    out: list[str] = []
    for item in raw.split(","):
        cleaned = item.strip().strip("`\"'[]")
        cleaned = cleaned.split()[-1] if " as " in cleaned.lower() else cleaned
        if "." in cleaned:
            cleaned = cleaned.rsplit(".", 1)[-1]
        if cleaned:
            out.append(cleaned)
    return out


def _php_source_fields(text: str) -> list[str]:
    fields = re.findall(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*['\"]([^'\"]+)['\"]", text, re.IGNORECASE)
    return [_normalize_field(field) for field in fields if _normalize_field(field)]


def _field_from_template_expr(expr: str) -> str:
    expr = expr.split("|", 1)[0].strip()
    return _field_from_expr(expr)


def _field_from_expr(expr: str) -> str:
    expr = str(expr or "")
    for pattern in (
        r"\.([A-Za-z_][A-Za-z0-9_]*)\b",
        r"\[['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\]",
        r"\$([A-Za-z_][A-Za-z0-9_]*)\b",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\b",
    ):
        matches = re.findall(pattern, expr)
        if not matches:
            continue
        for match in reversed(matches):
            field = _normalize_field(match)
            if field and field not in {"request", "form", "args", "values", "json", "files", "self"}:
                return field
    return ""


def _looks_sanitized(text: str) -> bool:
    return bool(SANITIZER_RE.search(text or ""))


def _normalize_field(value: Any) -> str:
    text = str(value or "").strip().strip("`\"'[]{}()")
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_").lower()


def _field_key(field: str) -> str:
    return f"field:{_normalize_field(field)}"


def _storage_id(field: str, kind: str) -> str:
    return f"storage:{kind}:{_normalize_field(field)}"


def _storage_label(field: str, kind: str, *, model: str | None = None) -> str:
    prefix = model or kind
    return f"{prefix}.{_normalize_field(field)}"


def _node_id(kind: str, rel: str, line: int, evidence: str) -> str:
    return f"{kind}:{_stable_hash(f'{rel}:{line}:{evidence}')[:14]}"


def _stable_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()


def _line_window(lines: list[str], line_no: int, *, radius: int) -> str:
    start = max(1, line_no)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start - 1 : end])


def _trim(value: Any, limit: int = 260) -> str:
    text = " ".join(str(value or "").strip().split())
    return text[:limit]


def _rel_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _dedupe_breakpoints(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out

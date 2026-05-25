from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.callscan.rules import should_skip_scan_path


@dataclass(slots=True)
class FunctionPool:
    """Global function-source pool shared by all CallScan traces."""

    functions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add(
        self,
        *,
        file: str,
        name: str,
        signature: str,
        start_line: int,
        end_line: int,
        source: str,
    ) -> str:
        function_ref = f"{file}:{start_line}:{end_line}:{name or 'anonymous'}"
        self.functions.setdefault(
            function_ref,
            {
                "function_ref": function_ref,
                "file": file,
                "name": name,
                "signature": signature,
                "start_line": start_line,
                "end_line": end_line,
                "source": source,
            },
        )
        return function_ref

    def as_dict(self) -> dict[str, dict[str, Any]]:
        return self.functions


@dataclass(slots=True)
class CodeSlicer:
    """Shared cache for source text, function snippets, and local backward slices."""

    root: Path
    function_pool: FunctionPool = field(default_factory=FunctionPool)
    file_cache: dict[str, list[str]] = field(default_factory=dict)
    tldr_extract_cache: dict[str, Any] = field(default_factory=dict)

    def read_source_lines(self, relative_path: str) -> list[str]:
        if relative_path not in self.file_cache:
            path = (self.root / relative_path).resolve()
            try:
                self.file_cache[relative_path] = path.read_text(encoding="utf-8").splitlines(keepends=True)
            except UnicodeDecodeError:
                self.file_cache[relative_path] = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            except OSError:
                self.file_cache[relative_path] = []
        return self.file_cache[relative_path]

    def add_function_from_block(self, *, file: str, block: dict[str, Any], lines: list[str]) -> str:
        start_line = int(block["start_line"])
        end_line = int(block["end_line"])
        return self.function_pool.add(
            file=file,
            name=str(block.get("symbol", "")),
            signature=str(block.get("signature", "")),
            start_line=start_line,
            end_line=end_line,
            source=slice_source_lines(lines, start_line, end_line),
        )

    def parse_parameters(self, signature: str, language: str) -> list[str]:
        return parse_parameters(signature, language)

    def build_backward_slice(
        self,
        *,
        lines: list[str],
        block: dict[str, Any],
        hit: dict[str, Any],
        scope_params: list[str],
    ) -> dict[str, Any]:
        sink_line = int(hit.get("line", 0) or 0)
        start_line = int(block["start_line"])
        sink_text = line_at(lines, sink_line)
        language = str(hit.get("language", ""))
        sink_argument = extract_sink_argument(sink_text, str(hit.get("match", "")), int(hit.get("column", 1) or 1))
        tracked_symbols = extract_identifiers(sink_argument, language)
        assignments: list[dict[str, Any]] = []
        source_candidates: list[dict[str, Any]] = []
        unresolved_symbols: set[str] = set(tracked_symbols)
        pending = list(tracked_symbols)
        visited: set[str] = set()

        while pending and len(visited) < 40:
            symbol = pending.pop(0)
            if symbol in visited:
                continue
            visited.add(symbol)
            assignment = find_previous_assignment(lines, start_line, sink_line, symbol)
            if not assignment:
                continue
            assignments.append(assignment)
            unresolved_symbols.discard(symbol)
            if looks_like_source(assignment["text"]):
                source_candidates.append(source_candidate_from_line(assignment, "assignment-source"))
            for dependency in extract_identifiers(assignment["rhs"], language):
                if dependency in scope_params:
                    source_candidates.append(
                        {
                            "kind": "function-parameter",
                            "symbol": dependency,
                            "line": int(block["start_line"]),
                            "evidence": str(block.get("signature", "")),
                            "confidence": "medium",
                        }
                    )
                    unresolved_symbols.discard(dependency)
                    continue
                if dependency not in visited and dependency not in pending:
                    pending.append(dependency)
                    unresolved_symbols.add(dependency)

        for symbol in tracked_symbols:
            if symbol in scope_params:
                source_candidates.append(
                    {
                        "kind": "function-parameter",
                        "symbol": symbol,
                        "line": int(block["start_line"]),
                        "evidence": str(block.get("signature", "")),
                        "confidence": "medium",
                    }
                )
                unresolved_symbols.discard(symbol)

        if looks_like_source(sink_argument) or looks_like_source(sink_text):
            source_candidates.append(
                {
                    "kind": "direct-source",
                    "symbol": "",
                    "line": sink_line,
                    "evidence": sink_text.strip(),
                    "confidence": "medium",
                }
            )

        deduped_sources = dedupe_dicts(source_candidates, ("kind", "symbol", "line", "evidence"))
        return {
            "sink_argument": sink_argument.strip(),
            "tracked_symbols": tracked_symbols,
            "assignments": assignments,
            "source_candidates": deduped_sources,
            "unresolved_symbols": sorted(unresolved_symbols),
            "confidence": slice_confidence(assignments, deduped_sources, unresolved_symbols),
            "notes": slice_notes(tracked_symbols, assignments, deduped_sources),
        }


def build_tldr_impact_paths(
    *,
    sink_analyses: list[dict[str, Any]],
    cross_file_edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Reverse-DFS static TLDR call graph from each sink scope to all reachable entry candidates."""

    callers_by_callee: dict[str, list[dict[str, Any]]] = {}
    for edge in cross_file_edges:
        to_node = _edge_node_key(edge.get("to", {}))
        if to_node:
            callers_by_callee.setdefault(to_node, []).append(edge)
        to_func = str(_object_or_empty(edge.get("to")).get("function", ""))
        if to_func:
            callers_by_callee.setdefault(to_func, []).append(edge)

    paths: list[dict[str, Any]] = []
    for analysis in sink_analyses:
        scope = _object_or_empty(analysis.get("enclosing_scope"))
        location = _object_or_empty(analysis.get("location"))
        start = {
            "file": location.get("file", ""),
            "function": scope.get("name", ""),
            "function_ref": scope.get("function_ref", ""),
        }
        start_key = _node_key(str(start["file"]), str(start["function"]))
        if not start_key:
            continue
        _dfs_tldr_impact(
            analysis_id=str(analysis.get("analysis_id", "")),
            current_key=start_key,
            current_node=start,
            callers_by_callee=callers_by_callee,
            path_nodes=[start],
            path_edges=[],
            seen={start_key},
            output=paths,
        )
    return paths


def filter_complete_impact_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only complete, non-cycle paths that reach a recognizable entry node."""

    complete: list[dict[str, Any]] = []
    for path in paths:
        if path.get("status") != "entry_reached":
            continue
        if path.get("termination") != "entry":
            continue
        if int(path.get("depth", 0) or 0) <= 0:
            continue
        if any(_object_or_empty(edge).get("confidence") == "low" for edge in path.get("edges", [])):
            continue
        if any(should_skip_scan_path(str(_object_or_empty(node).get("file", ""))) for node in path.get("nodes", [])):
            continue
        complete.append(path)
    return complete


def format_audit_pack(
    *,
    candidate_path: dict[str, Any],
    function_pool: FunctionPool | dict[str, Any],
) -> dict[str, Any]:
    """Render one auditor-friendly pack: chain + call edges + de-duplicated function bodies."""

    pool = function_pool.as_dict() if isinstance(function_pool, FunctionPool) else function_pool
    refs: list[str] = []
    for node in candidate_path.get("nodes", []):
        if isinstance(node, dict) and node.get("function_ref"):
            refs.append(str(node["function_ref"]))

    unique_refs = unique(refs)
    return {
        "path_id": candidate_path.get("path_id", ""),
        "analysis_id": candidate_path.get("analysis_id", ""),
        "status": candidate_path.get("status", ""),
        "chain": candidate_path.get("nodes", []),
        "call_edges": candidate_path.get("edges", []),
        "functions": [pool[ref] for ref in unique_refs if ref in pool],
    }


def _dfs_tldr_impact(
    *,
    analysis_id: str,
    current_key: str,
    current_node: dict[str, Any],
    callers_by_callee: dict[str, list[dict[str, Any]]],
    path_nodes: list[dict[str, Any]],
    path_edges: list[dict[str, Any]],
    seen: set[str],
    output: list[dict[str, Any]],
) -> None:
    incoming = callers_by_callee.get(current_key, [])
    current_func = str(current_node.get("function", "") or current_node.get("name", ""))
    if not incoming and current_func:
        incoming = callers_by_callee.get(current_func, [])
    if is_entry_candidate(current_node):
        output.append(_impact_path(analysis_id, path_nodes, path_edges, "entry_reached", termination="entry"))
        return
    if not incoming:
        output.append(_impact_path(analysis_id, path_nodes, path_edges, "incomplete_leaf", termination="no_caller"))
        return

    for edge in incoming:
        caller = _object_or_empty(edge.get("from"))
        caller_key = _edge_node_key(caller)
        if not caller_key:
            continue
        if caller_key in seen:
            output.append(_impact_path(analysis_id, [*path_nodes, caller], [*path_edges, edge], "cycle", termination="cycle"))
            continue
        _dfs_tldr_impact(
            analysis_id=analysis_id,
            current_key=caller_key,
            current_node=caller,
            callers_by_callee=callers_by_callee,
            path_nodes=[*path_nodes, caller],
            path_edges=[*path_edges, edge],
            seen={*seen, caller_key},
            output=output,
        )


def _impact_path(
    analysis_id: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    status: str,
    *,
    termination: str,
) -> dict[str, Any]:
    return {
        "path_id": f"impact:{analysis_id}:{len(nodes)}:{abs(hash(tuple(_edge_node_key(node) for node in nodes))) % 100000000}",
        "analysis_id": analysis_id,
        "status": status,
        "termination": termination,
        "complete": status == "entry_reached" and termination == "entry" and len(nodes) > 1,
        "nodes": nodes,
        "edges": edges,
        "depth": max(len(nodes) - 1, 0),
    }


def is_entry_candidate(node: dict[str, Any]) -> bool:
    name = str(node.get("function", "") or node.get("name", "")).casefold()
    if not name:
        return False
    markers = ("action", "controller", "route", "handle", "main", "dispatch", "hook")
    return any(marker in name for marker in markers) or name in {"run", "execute", "__invoke"}


def slice_source_lines(lines: list[str], start_line: int, end_line: int) -> str:
    return "".join(lines[start_line - 1 : end_line])


def line_at(lines: list[str], line_number: int) -> str:
    if line_number <= 0 or line_number > len(lines):
        return ""
    return lines[line_number - 1]


def parse_parameters(signature: str, language: str) -> list[str]:
    match = re.search(r"\((?P<params>.*)\)", signature)
    if not match:
        return []
    parsed: list[str] = []
    for param in split_arguments(match.group("params")):
        cleaned = param.strip()
        if not cleaned:
            continue
        cleaned = cleaned.split("=")[0].strip().replace("*", " ").replace("&", " ")
        identifiers = extract_identifiers(cleaned, language)
        if identifiers:
            parsed.append(identifiers[-1])
    return unique(parsed)


def extract_sink_argument(line: str, matched_text: str, column: int) -> str:
    call_start = max(column - 1, 0)
    if matched_text:
        found = line.find(matched_text, max(call_start - 4, 0))
        if found >= 0:
            call_start = found
    paren = line.find("(", call_start)
    if paren < 0:
        return line.strip()
    close = find_matching_paren(line, paren)
    if close < 0:
        return line[paren + 1 :].strip()
    args = split_arguments(line[paren + 1 : close])
    return args[0] if args else line[paren + 1 : close].strip()


def extract_call_arguments(line: str, callee_symbol: str) -> list[str]:
    match = re.search(rf"\b{re.escape(callee_symbol)}\s*\(", line)
    if not match:
        return []
    paren = line.find("(", match.start())
    close = find_matching_paren(line, paren)
    if close < 0:
        return split_arguments(line[paren + 1 :])
    return split_arguments(line[paren + 1 : close])


def split_arguments(text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    escaped = False
    for char in text:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
            current.append(char)
            continue
        if char in ")]}":
            depth = max(depth - 1, 0)
            current.append(char)
            continue
        if char == "," and depth == 0:
            value = "".join(current).strip()
            if value:
                args.append(value)
            current = []
            continue
        current.append(char)
    value = "".join(current).strip()
    if value:
        args.append(value)
    return args


def find_matching_paren(text: str, start: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def extract_identifiers(text: str, language: str) -> list[str]:
    stripped = re.sub(r"(['\"`]).*?\1", " ", text)
    variables = [item.lstrip("$") for item in re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", stripped)] if language.casefold() == "php" else []
    identifiers = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped)
    ignored = {
        "and", "as", "async", "await", "break", "case", "catch", "class", "const", "def",
        "else", "false", "for", "foreach", "function", "if", "import", "in", "let", "new",
        "none", "null", "or", "return", "self", "static", "this", "true", "var", "void", "while",
    }
    return unique([*variables, *(item for item in identifiers if item.casefold() not in ignored)])


def find_previous_assignment(lines: list[str], start_line: int, sink_line: int, symbol: str) -> dict[str, Any] | None:
    symbol_pattern = re.escape(symbol)
    patterns = [
        re.compile(rf"(?P<lhs>\${symbol_pattern})\s*=\s*(?P<rhs>.+)"),
        re.compile(rf"\b(?:let|const|var)\s+(?P<lhs>{symbol_pattern})\s*=\s*(?P<rhs>.+)"),
        re.compile(rf"\b(?P<lhs>{symbol_pattern})\s*(?::=|=)\s*(?P<rhs>.+)"),
        re.compile(rf"\b(?P<lhs>{symbol_pattern})\s*:\s*[^=]+=\s*(?P<rhs>.+)"),
    ]
    for line_number in range(sink_line - 1, max(start_line - 1, 0), -1):
        text = lines[line_number - 1].strip()
        if not text or text.startswith(("#", "//", "*")):
            continue
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return {
                    "symbol": symbol,
                    "line": line_number,
                    "text": text,
                    "rhs": match.group("rhs").strip().rstrip(";"),
                    "confidence": "medium",
                }
    return None


def looks_like_source(text: str) -> bool:
    lowered = text.casefold()
    markers = (
        "$_get", "$_post", "$_request", "$_cookie", "$_files", "request.", "request->",
        "request[", "req.", "req[", "input(", "input.", "param", "query", "body",
        "cookie", "header", "getenv", "os.environ", "stdin", "formfile", "multipart", "url.query",
    )
    return any(marker in lowered for marker in markers)


def source_candidate_from_line(assignment: dict[str, Any], kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "symbol": assignment.get("symbol", ""),
        "line": assignment.get("line", 0),
        "evidence": assignment.get("text", ""),
        "confidence": "medium",
    }


def slice_confidence(assignments: list[dict[str, Any]], source_candidates: list[dict[str, Any]], unresolved_symbols: set[str]) -> str:
    if source_candidates and not unresolved_symbols:
        return "high"
    if source_candidates or assignments:
        return "medium"
    return "low"


def slice_notes(tracked_symbols: list[str], assignments: list[dict[str, Any]], source_candidates: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    if not tracked_symbols:
        notes.append("sink argument did not expose a simple local symbol")
    if tracked_symbols and not assignments:
        notes.append("no local assignment found before sink line")
    if source_candidates:
        notes.append("source candidate found by local lexical markers")
    return notes


def dedupe_dicts(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    unique_items: list[dict[str, Any]] = []
    for item in items:
        key = tuple(item.get(name) for name in keys)
        if key in seen:
            continue
        seen.add(key)
        unique_items.append(item)
    return unique_items


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _edge_node_key(value: Any) -> str:
    node = _object_or_empty(value)
    return _node_key(str(node.get("file", "")), str(node.get("function", "")))


def _node_key(file: str, function: str) -> str:
    if not function:
        return ""
    return f"{file}:{function}"


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}

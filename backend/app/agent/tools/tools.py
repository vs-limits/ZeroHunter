from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


DEFAULT_CONTEXT_RADIUS = 40
MAX_SEARCH_RESULTS = 50


def read_file_window(
    repo_root: str | Path,
    file_path: str | Path,
    *,
    line: int | None = None,
    radius: int = DEFAULT_CONTEXT_RADIUS,
    start_line: int | None = None,
    end_line: int | None = None,
) -> dict[str, Any]:
    """Read a bounded source window under repo_root."""
    root = Path(repo_root).resolve()
    path = _safe_repo_path(root, file_path)
    lines = _read_lines(path)
    if not lines:
        return _window_result(root, path, 0, 0, [])

    if start_line is None or end_line is None:
        center = max(int(line or 1), 1)
        start_line = max(center - radius, 1)
        end_line = min(center + radius, len(lines))
    else:
        start_line = max(int(start_line), 1)
        end_line = min(int(end_line), len(lines))

    return _window_result(root, path, start_line, end_line, lines[start_line - 1 : end_line])


def search_code(
    repo_root: str | Path,
    pattern: str,
    *,
    include_globs: list[str] | None = None,
    max_results: int = MAX_SEARCH_RESULTS,
) -> list[dict[str, Any]]:
    """Search code with ripgrep and return normalized repo-relative matches."""
    root = Path(repo_root).resolve()
    rg = shutil.which("rg.exe") or shutil.which("rg") or "rg.exe"
    command = [rg, "-u", "--json", "-n", "--column", "-S", "-e", pattern]
    for glob in include_globs or []:
        command.extend(["-g", glob])
    command.append(str(root))

    completed = subprocess.run(
        command,
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(f"rg search failed with code {completed.returncode}: {completed.stderr.strip()}")

    hits: list[dict[str, Any]] = []
    for raw_line in completed.stdout.splitlines():
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "match":
            continue
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        path = str((data.get("path") or {}).get("text", ""))
        text = str((data.get("lines") or {}).get("text", "")).rstrip("\r\n")
        for submatch in data.get("submatches", []):
            if not isinstance(submatch, dict):
                continue
            hits.append(
                {
                    "file": _relative(root, Path(path)),
                    "line": int(data.get("line_number", 0) or 0),
                    "column": int(submatch.get("start", 0) or 0) + 1,
                    "match": str((submatch.get("match") or {}).get("text", "")),
                    "evidence": text.strip(),
                }
            )
            if len(hits) >= max_results:
                return hits
    return hits


def extract_function(
    repo_root: str | Path,
    file_path: str | Path,
    *,
    function: str | None = None,
    line: int | None = None,
    radius: int = 80,
) -> dict[str, Any]:
    """Best-effort function extraction for tool-driven audit context."""
    root = Path(repo_root).resolve()
    path = _safe_repo_path(root, file_path)
    lines = _read_lines(path)
    if not lines:
        return _window_result(root, path, 0, 0, [])

    target_line = int(line or 0)
    if target_line <= 0 and function:
        target_line = _find_function_line(lines, function)
    if target_line <= 0:
        target_line = 1

    start_line, end_line = _guess_block_bounds(lines, target_line)
    if start_line == end_line:
        return read_file_window(root, path, line=target_line, radius=radius)
    return _window_result(root, path, start_line, end_line, lines[start_line - 1 : end_line])


def trace_impact(
    repo_root: str | Path,
    *,
    function: str,
    file_path: str | None = None,
    max_depth: int = 4,
) -> dict[str, Any]:
    """Trace reverse callers from the static TLDR cache when available."""
    root = Path(repo_root).resolve()
    graph = _load_tldr_call_graph(root)
    if not graph:
        return {"enabled": False, "status": "missing_tldr_cache", "paths": []}

    edges = [edge for edge in graph.get("edges", []) if isinstance(edge, dict)]
    callers_by_to: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        to_node = edge.get("to") if isinstance(edge.get("to"), dict) else {}
        callers_by_to.setdefault(_node_key(to_node), []).append(edge)
        to_function = str(to_node.get("function", ""))
        if to_function:
            callers_by_to.setdefault(to_function, []).append(edge)

    start = {"file": file_path or "", "function": function}
    paths: list[dict[str, Any]] = []
    _trace_reverse(
        current=start,
        callers_by_to=callers_by_to,
        path_nodes=[start],
        path_edges=[],
        seen={_node_key(start)},
        output=paths,
        max_depth=max_depth,
    )
    return {"enabled": True, "status": "ok", "paths": paths}


def _trace_reverse(
    *,
    current: dict[str, Any],
    callers_by_to: dict[str, list[dict[str, Any]]],
    path_nodes: list[dict[str, Any]],
    path_edges: list[dict[str, Any]],
    seen: set[str],
    output: list[dict[str, Any]],
    max_depth: int,
) -> None:
    if len(path_edges) >= max_depth:
        output.append({"status": "depth_limit", "nodes": path_nodes, "edges": path_edges})
        return
    incoming = callers_by_to.get(_node_key(current), []) or callers_by_to.get(str(current.get("function", "")), [])
    if not incoming:
        output.append({"status": "leaf", "nodes": path_nodes, "edges": path_edges})
        return
    for edge in incoming:
        caller = edge.get("from") if isinstance(edge.get("from"), dict) else {}
        key = _node_key(caller)
        if not key or key in seen:
            output.append({"status": "cycle", "nodes": [*path_nodes, caller], "edges": [*path_edges, edge]})
            continue
        _trace_reverse(
            current=caller,
            callers_by_to=callers_by_to,
            path_nodes=[*path_nodes, caller],
            path_edges=[*path_edges, edge],
            seen={*seen, key},
            output=output,
            max_depth=max_depth,
        )


def _load_tldr_call_graph(root: Path) -> dict[str, Any]:
    candidates = [
        root / ".tldr" / "cache" / "call_graph.json",
        root.parent / ".tldr" / "cache" / "call_graph.json",
        Path.cwd() / ".tldr" / "cache" / "call_graph.json",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    return {}


def _safe_repo_path(root: Path, path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {resolved}") from exc
    return resolved


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _window_result(root: Path, path: Path, start_line: int, end_line: int, lines: list[str]) -> dict[str, Any]:
    return {
        "file": _relative(root, path),
        "start_line": start_line,
        "end_line": end_line,
        "source": "\n".join(lines),
    }


def _find_function_line(lines: list[str], function: str) -> int:
    escaped = re.escape(function)
    pattern = re.compile(
        rf"\b((?:public|private|protected|static)\s+)*function\s+{escaped}\s*\(|\bdef\s+{escaped}\s*\(",
        re.IGNORECASE,
    )
    for index, line in enumerate(lines, start=1):
        if pattern.search(line):
            return index
    fallback = re.compile(rf"\b{escaped}\s*\(", re.IGNORECASE)
    for index, line in enumerate(lines, start=1):
        if fallback.search(line):
            return index
    return 0


def _guess_block_bounds(lines: list[str], line_number: int) -> tuple[int, int]:
    start = max(line_number, 1)
    while start > 1 and not _looks_like_block_start(lines[start - 1]):
        start -= 1

    depth = 0
    saw_brace = False
    for index in range(start, len(lines) + 1):
        line = lines[index - 1]
        depth += line.count("{") - line.count("}")
        saw_brace = saw_brace or "{" in line
        if saw_brace and depth <= 0 and index > start:
            return start, index

    base_indent = len(lines[start - 1]) - len(lines[start - 1].lstrip())
    for index in range(start + 1, len(lines) + 1):
        text = lines[index - 1]
        if text.strip() and len(text) - len(text.lstrip()) <= base_indent:
            return start, index - 1
    return start, min(start + DEFAULT_CONTEXT_RADIUS, len(lines))


def _looks_like_block_start(line: str) -> bool:
    return bool(re.search(r"\b(function|def|class|public|private|protected|static|async)\b", line))


def _node_key(node: dict[str, Any]) -> str:
    file = str(node.get("file", ""))
    function = str(node.get("function", "") or node.get("name", ""))
    return f"{file}:{function}" if file or function else ""


def _relative(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return str(path).replace("\\", "/")


__all__ = [
    "extract_function",
    "trace_impact",
    "search_code",
    "read_file_window",
]

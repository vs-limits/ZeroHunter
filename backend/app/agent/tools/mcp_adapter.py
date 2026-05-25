from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SUPPORTED_TOOL_NAMES = {
    "ripgrep__search",
    "read_file_window",
    "tldr__tldr_extract",
    "tldr__tldr_impact",
}

DEFAULT_RG_TIMEOUT_SECONDS = 20
DEFAULT_MAX_RG_MATCHES = 200
DEFAULT_MAX_FILE_LINES = 220
DEFAULT_TLDR_IMPACT_DEPTH = 8


#----------- MCP 工具调用结构：把 LLM 发来的 tool name / arguments 固定成可测试对象 ------------#
@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ToolCall":
        name = str(payload.get("name") or payload.get("tool") or "").strip()
        arguments = payload.get("arguments") or payload.get("args") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        call_id = payload.get("id") or payload.get("call_id")
        return cls(name=name, arguments=arguments, call_id=str(call_id) if call_id else None)


#----------- MCP 工具返回结构：所有本地工具统一返回 ok/data/error，方便 Scanner Agent 消费 ------------#
@dataclass(frozen=True, slots=True)
class ToolResult:
    name: str
    ok: bool
    data: dict[str, Any]
    error: str | None = None
    call_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "tool": self.name,
            "ok": self.ok,
            "data": self.data,
        }
        if self.error:
            payload["error"] = self.error
        if self.call_id:
            payload["call_id"] = self.call_id
        return payload


#----------- MCP 工具循环适配层：按工具名分发到本地 rg、文件窗口、静态 TLDR cache ------------#
class ToolLoopAdapter:
    def __init__(
        self,
        project_root: str | Path,
        *,
        rg_path: str | Path | None = None,
        tldr_cache_path: str | Path | None = None,
    ) -> None:
        self.project_root = Path(project_root).expanduser().resolve()
        if not self.project_root.is_dir():
            raise NotADirectoryError(f"Project root is not a directory: {self.project_root}")

        self.rg_path = str(_find_rg_path(self.project_root, rg_path))
        self.tldr = StaticTldrCache(self.project_root, cache_path=tldr_cache_path)

    def run(self, call: ToolCall | dict[str, Any]) -> ToolResult:
        tool_call = call if isinstance(call, ToolCall) else ToolCall.from_payload(call)

        try:
            if tool_call.name == "ripgrep__search":
                data = ripgrep_search(
                    self.project_root,
                    rg_path=self.rg_path,
                    **tool_call.arguments,
                )
            elif tool_call.name == "read_file_window":
                data = read_file_window(self.project_root, **tool_call.arguments)
            elif tool_call.name == "tldr__tldr_extract":
                data = self.tldr.extract(**tool_call.arguments)
            elif tool_call.name == "tldr__tldr_impact":
                data = self.tldr.impact(**tool_call.arguments)
            else:
                supported = ", ".join(sorted(SUPPORTED_TOOL_NAMES))
                raise ValueError(f"Unsupported tool: {tool_call.name}. Supported tools: {supported}")

            return ToolResult(
                name=tool_call.name,
                ok=True,
                data=data,
                call_id=tool_call.call_id,
            )
        except Exception as exc:
            return ToolResult(
                name=tool_call.name or "unknown",
                ok=False,
                data={},
                error=str(exc),
                call_id=tool_call.call_id,
            )

    def run_many(self, calls: Iterable[ToolCall | dict[str, Any]]) -> list[ToolResult]:
        return [self.run(call) for call in calls]


def run_tool_call(
    project_root: str | Path,
    call: ToolCall | dict[str, Any],
    *,
    rg_path: str | Path | None = None,
    tldr_cache_path: str | Path | None = None,
) -> ToolResult:
    adapter = ToolLoopAdapter(project_root, rg_path=rg_path, tldr_cache_path=tldr_cache_path)
    return adapter.run(call)


def run_tool_calls(
    project_root: str | Path,
    calls: Iterable[ToolCall | dict[str, Any]],
    *,
    rg_path: str | Path | None = None,
    tldr_cache_path: str | Path | None = None,
) -> list[ToolResult]:
    adapter = ToolLoopAdapter(project_root, rg_path=rg_path, tldr_cache_path=tldr_cache_path)
    return adapter.run_many(calls)


#----------- ripgrep__search：使用 subprocess 调 rg -u --json，返回结构化命中而不是散文本 ------------#
def ripgrep_search(
    project_root: str | Path,
    pattern: str,
    *,
    rg_path: str | Path = "rg",
    path: str | None = None,
    glob: str | list[str] | None = None,
    case_sensitive: bool = True,
    fixed_strings: bool = False,
    context_lines: int = 0,
    max_matches: int = DEFAULT_MAX_RG_MATCHES,
    timeout_seconds: int = DEFAULT_RG_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    root = _validate_root(project_root)
    search_base = _resolve_path(root, path) if path else root

    args = [
        str(rg_path),
        "--json",
        "--line-number",
        "--column",
        "--color",
        "never",
        "-u",
    ]
    if not case_sensitive:
        args.append("--ignore-case")
    if fixed_strings:
        args.append("--fixed-strings")
    if context_lines > 0:
        args.extend(["--context", str(int(context_lines))])
    for item in _normalize_globs(glob):
        args.extend(["--glob", item])
    args.extend([pattern, str(search_base)])

    completed = subprocess.run(
        args,
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )

    matches = _parse_rg_json_lines(root, completed.stdout, max_matches=max_matches)
    return {
        "pattern": pattern,
        "root": str(root),
        "search_base": _relative_or_absolute(root, search_base),
        "rg_path": str(rg_path),
        "exit_code": completed.returncode,
        "truncated": len(matches) >= max_matches,
        "match_count": len(matches),
        "matches": matches,
        "stderr": completed.stderr.strip()[:2000],
    }


def search_code(project_root: str | Path, query: str, **kwargs: Any) -> dict[str, Any]:
    return ripgrep_search(project_root, query, **kwargs)


#----------- read_file_window：本地读取文件窗口，给 LLM 补 sink 附近或调用点附近源码 ------------#
def read_file_window(
    project_root: str | Path,
    file_path: str,
    *,
    start_line: int | None = None,
    end_line: int | None = None,
    center_line: int | None = None,
    before: int = 30,
    after: int = 80,
    max_lines: int = DEFAULT_MAX_FILE_LINES,
) -> dict[str, Any]:
    root = _validate_root(project_root)
    path = _resolve_path(root, file_path)
    lines = _read_text_lines(path)
    total = len(lines)

    if center_line is not None:
        start = max(int(center_line) - int(before), 1)
        end = min(int(center_line) + int(after), total)
    else:
        start = int(start_line or 1)
        end = int(end_line or min(start + int(max_lines) - 1, total))

    start = max(start, 1)
    end = min(max(end, start), total)
    if end - start + 1 > max_lines:
        end = start + max_lines - 1

    window = [
        {
            "line": line_number,
            "text": lines[line_number - 1],
        }
        for line_number in range(start, end + 1)
    ]
    return {
        "file_path": _relative_or_absolute(root, path),
        "absolute_path": str(path),
        "start_line": start,
        "end_line": end,
        "total_lines": total,
        "truncated": end < total or start > 1,
        "lines": window,
        "text": "\n".join(f"{item['line']}: {item['text']}" for item in window),
    }


#----------- tldr__tldr_extract：优先读取静态 TLDR cache，命中失败时返回文件窗口式静态结果 ------------#
def tldr_extract(
    project_root: str | Path,
    *,
    file_path: str | None = None,
    function_name: str | None = None,
    function_ref: str | None = None,
    line: int | None = None,
    cache_path: str | Path | None = None,
) -> dict[str, Any]:
    cache = StaticTldrCache(project_root, cache_path=cache_path)
    return cache.extract(file_path=file_path, function_name=function_name, function_ref=function_ref, line=line)


def extract_function(project_root: str | Path, **kwargs: Any) -> dict[str, Any]:
    return tldr_extract(project_root, **kwargs)


#----------- tldr__tldr_impact：基于静态 TLDR 反向调用图做 impact 追踪，不启动动态 MCP ------------#
def tldr_impact(
    project_root: str | Path,
    *,
    file_path: str | None = None,
    function_name: str | None = None,
    function_ref: str | None = None,
    line: int | None = None,
    max_depth: int = DEFAULT_TLDR_IMPACT_DEPTH,
    cache_path: str | Path | None = None,
) -> dict[str, Any]:
    cache = StaticTldrCache(project_root, cache_path=cache_path)
    return cache.impact(
        file_path=file_path,
        function_name=function_name,
        function_ref=function_ref,
        line=line,
        max_depth=max_depth,
    )


def trace_impact(project_root: str | Path, **kwargs: Any) -> dict[str, Any]:
    return tldr_impact(project_root, **kwargs)


class StaticTldrCache:
    def __init__(self, project_root: str | Path, *, cache_path: str | Path | None = None) -> None:
        self.root = _validate_root(project_root)
        self.cache_path = _find_tldr_cache_path(self.root, cache_path)
        self.raw: dict[str, Any] = {}
        self.functions: list[dict[str, Any]] = []
        self.by_ref: dict[str, dict[str, Any]] = {}

        if self.cache_path:
            self.raw = _read_json(self.cache_path)
            self.functions = _collect_function_nodes(self.raw, self.root)
            self.by_ref = {item["function_ref"]: item for item in self.functions if item.get("function_ref")}

    def extract(
        self,
        *,
        file_path: str | None = None,
        function_name: str | None = None,
        function_ref: str | None = None,
        line: int | None = None,
    ) -> dict[str, Any]:
        matches = self._match_functions(
            file_path=file_path,
            function_name=function_name,
            function_ref=function_ref,
            line=line,
        )

        if matches:
            return {
                "source": "static_tldr_cache",
                "cache_path": str(self.cache_path) if self.cache_path else None,
                "match_count": len(matches),
                "functions": matches,
            }

        fallback = self._fallback_extract_from_file(file_path=file_path, line=line)
        fallback.update(
            {
                "source": "local_static_file",
                "cache_path": str(self.cache_path) if self.cache_path else None,
                "match_count": 0,
            }
        )
        return fallback

    def impact(
        self,
        *,
        file_path: str | None = None,
        function_name: str | None = None,
        function_ref: str | None = None,
        line: int | None = None,
        max_depth: int = DEFAULT_TLDR_IMPACT_DEPTH,
    ) -> dict[str, Any]:
        starts = self._match_functions(
            file_path=file_path,
            function_name=function_name,
            function_ref=function_ref,
            line=line,
        )
        reverse_edges = self._reverse_edges()
        paths: list[list[dict[str, Any]]] = []

        for start in starts:
            self._walk_callers(
                start,
                reverse_edges=reverse_edges,
                path=[],
                paths=paths,
                seen=set(),
                max_depth=max_depth,
            )

        return {
            "source": "static_tldr_cache" if self.cache_path else "missing_static_tldr_cache",
            "cache_path": str(self.cache_path) if self.cache_path else None,
            "start_count": len(starts),
            "path_count": len(paths),
            "paths": paths,
            "complete_paths": [path for path in paths if _looks_like_entry(path[-1] if path else {})],
        }

    def _match_functions(
        self,
        *,
        file_path: str | None,
        function_name: str | None,
        function_ref: str | None,
        line: int | None,
    ) -> list[dict[str, Any]]:
        if function_ref and function_ref in self.by_ref:
            return [self.by_ref[function_ref]]

        normalized_file = _normalize_relative_path(file_path) if file_path else None
        wanted_name = function_name.lower() if function_name else None
        wanted_line = int(line) if line is not None else None

        matches: list[dict[str, Any]] = []
        for item in self.functions:
            item_file = _normalize_relative_path(str(item.get("file_path", "")))
            item_name = str(item.get("name", "")).lower()

            if normalized_file and item_file != normalized_file:
                continue
            if wanted_name and item_name != wanted_name:
                continue
            if wanted_line is not None:
                start = int(item.get("start_line") or 0)
                end = int(item.get("end_line") or start)
                if start and end and not (start <= wanted_line <= end):
                    continue
            matches.append(item)

        return matches[:20]

    def _fallback_extract_from_file(self, *, file_path: str | None, line: int | None) -> dict[str, Any]:
        if not file_path:
            return {"functions": [], "fallback_reason": "file_path is required when TLDR cache misses"}
        center_line = int(line) if line else 1
        window = read_file_window(self.root, file_path, center_line=center_line, before=80, after=140)
        return {
            "functions": [
                {
                    "function_ref": f"{window['file_path']}:{window['start_line']}-{window['end_line']}",
                    "name": "unknown",
                    "file_path": window["file_path"],
                    "start_line": window["start_line"],
                    "end_line": window["end_line"],
                    "code": window["text"],
                    "calls": [],
                    "callers": [],
                    "confidence": "fallback_window",
                }
            ],
            "fallback_reason": "static TLDR cache did not contain the requested function",
        }

    def _reverse_edges(self) -> dict[str, list[str]]:
        reverse: dict[str, list[str]] = {}
        for item in self.functions:
            current_ref = item.get("function_ref")
            if not current_ref:
                continue
            for caller_ref in _as_list(item.get("callers") or item.get("called_by")):
                caller_key = _edge_ref(caller_ref)
                if caller_key:
                    reverse.setdefault(current_ref, []).append(caller_key)
            for callee_ref in _as_list(item.get("calls") or item.get("callees")):
                callee_key = _edge_ref(callee_ref)
                if callee_key:
                    reverse.setdefault(callee_key, []).append(current_ref)
        return reverse

    def _walk_callers(
        self,
        node: dict[str, Any],
        *,
        reverse_edges: dict[str, list[str]],
        path: list[dict[str, Any]],
        paths: list[list[dict[str, Any]]],
        seen: set[str],
        max_depth: int,
    ) -> None:
        ref = str(node.get("function_ref", ""))
        current_path = path + [_strip_function_for_path(node)]
        if not ref or ref in seen or len(current_path) >= max_depth:
            paths.append(current_path)
            return

        callers = [self.by_ref[item] for item in reverse_edges.get(ref, []) if item in self.by_ref]
        if not callers:
            paths.append(current_path)
            return

        next_seen = set(seen)
        next_seen.add(ref)
        for caller in callers[:30]:
            self._walk_callers(
                caller,
                reverse_edges=reverse_edges,
                path=current_path,
                paths=paths,
                seen=next_seen,
                max_depth=max_depth,
            )


def _parse_rg_json_lines(root: Path, stdout: str, *, max_matches: int) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        if len(matches) >= max_matches:
            break
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "match":
            continue

        data = event.get("data", {})
        path = Path(data.get("path", {}).get("text", ""))
        submatches = data.get("submatches", [])
        matches.append(
            {
                "file_path": _relative_or_absolute(root, path if path.is_absolute() else root / path),
                "line_number": data.get("line_number"),
                "absolute_offset": data.get("absolute_offset"),
                "line": data.get("lines", {}).get("text", "").rstrip("\n\r"),
                "submatches": [
                    {
                        "match": sub.get("match", {}).get("text", ""),
                        "start": sub.get("start"),
                        "end": sub.get("end"),
                    }
                    for sub in submatches
                ],
            }
        )
    return matches


def _collect_function_nodes(raw: Any, root: Path) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    for item in _walk_possible_nodes(raw):
        normalized = _normalize_function_node(item, root)
        if normalized:
            nodes.append(normalized)
    return nodes


def _walk_possible_nodes(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if _looks_like_function_node(value):
            yield value
        for child in value.values():
            yield from _walk_possible_nodes(child)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_possible_nodes(item)


def _looks_like_function_node(item: dict[str, Any]) -> bool:
    has_name = any(key in item for key in ("name", "function_name", "symbol"))
    has_path = any(key in item for key in ("file_path", "path", "file"))
    has_lines = any(key in item for key in ("start_line", "line", "start"))
    return has_name and has_path and has_lines


def _normalize_function_node(item: dict[str, Any], root: Path) -> dict[str, Any] | None:
    raw_path = item.get("file_path") or item.get("path") or item.get("file")
    if not raw_path:
        return None

    file_path = _normalize_relative_path(_relative_or_absolute(root, Path(str(raw_path))))
    name = str(item.get("name") or item.get("function_name") or item.get("symbol") or "unknown")
    start_line = _to_int(item.get("start_line") or item.get("line") or item.get("start"))
    end_line = _to_int(item.get("end_line") or item.get("end") or start_line)
    function_ref = str(item.get("function_ref") or item.get("id") or f"{file_path}::{name}:{start_line}")

    return {
        "function_ref": function_ref,
        "name": name,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "signature": item.get("signature") or "",
        "code": item.get("code") or item.get("source") or "",
        "calls": _as_list(item.get("calls") or item.get("callees")),
        "callers": _as_list(item.get("callers") or item.get("called_by")),
        "entrypoint": bool(item.get("entrypoint") or item.get("is_entrypoint") or False),
        "raw_kind": item.get("kind") or item.get("type") or "function",
    }


def _strip_function_for_path(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "function_ref": item.get("function_ref"),
        "name": item.get("name"),
        "file_path": item.get("file_path"),
        "start_line": item.get("start_line"),
        "end_line": item.get("end_line"),
        "entrypoint": item.get("entrypoint", False),
    }


def _looks_like_entry(item: dict[str, Any]) -> bool:
    if item.get("entrypoint"):
        return True
    path = str(item.get("file_path", "")).lower()
    name = str(item.get("name", "")).lower()
    return any(part in path for part in ("actions/", "handlers/", "controllers/", "routes/")) or name in {
        "__construct",
        "handle",
        "run",
        "execute",
    }


def _find_tldr_cache_path(root: Path, explicit: str | Path | None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        raw_explicit = Path(explicit).expanduser()
        candidates.append(raw_explicit if raw_explicit.is_absolute() else root / raw_explicit)
    candidates.extend(
        [
            root / ".tldr" / "cache" / "call_graph.json",
            root / ".defectmine" / "tldr" / "call_graph.json",
            root / ".defectmine" / "call_graph.json",
            Path.cwd() / ".tldr" / "cache" / "call_graph.json",
        ]
    )

    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file():
            return resolved
    return None


def _find_rg_path(root: Path, explicit: str | Path | None) -> Path | str:
    if explicit:
        raw = Path(explicit).expanduser()
        return raw if raw.is_absolute() else (root / raw).resolve()

    env_rg = os.environ.get("DEFECTMINE_RG")
    if env_rg:
        return env_rg

    for base in (root, _workspace_root(root), Path.cwd()):
        candidate = base / "ripgrep" / "rg.exe"
        if candidate.is_file():
            return candidate

    return "rg"


def _workspace_root(root: Path) -> Path:
    for parent in (root, *root.parents):
        if (parent / "backend").is_dir() and (parent / "repo_code").is_dir():
            return parent
    return Path.cwd()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        parsed = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(parsed, dict):
        return parsed
    return {"items": parsed}


def _read_text_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _validate_root(project_root: str | Path) -> Path:
    root = Path(project_root).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Project root is not a directory: {root}")
    return root


def _resolve_path(root: Path, file_path: str | Path | None) -> Path:
    if not file_path:
        return root
    raw = Path(file_path).expanduser()
    path = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Path escapes project root: {file_path}") from exc
    return path


def _relative_or_absolute(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return _normalize_relative_path(str(resolved.relative_to(root)))
    except ValueError:
        return _normalize_relative_path(str(path))


def _normalize_relative_path(path: str | None) -> str:
    if not path:
        return ""
    return str(path).replace("\\", "/").lstrip("./")


def _normalize_globs(glob: str | list[str] | None) -> list[str]:
    if glob is None:
        return []
    if isinstance(glob, str):
        return [glob]
    return [str(item) for item in glob if str(item).strip()]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _edge_ref(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        ref = value.get("function_ref") or value.get("id") or value.get("target") or value.get("source")
        return str(ref) if ref else None
    return None


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

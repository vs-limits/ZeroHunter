"""调用链源码切片 + 全局函数池。

设计目标
========
1. **广度 + 深度全枚举**：从 sink 出发反向 DFS tldr_impact 树，把所有可达
   entry point 的路径都算出来；不主动截链长，唯一终止条件是 entry / cycle。
2. **token 友好**：所有函数源码只存到全局 `FunctionPool` 里一次，链节点
   只携带 function_ref（一个轻量字符串 key）。Auditor 拿一个候选时通过
   `format_audit_pack` 渲染：链结构 + 调用点代码 + 候选内去重的函数体。
3. **共享缓存**：`CodeSlicer` 缓存 tldr_extract 与文件文本，整条 CallScan
   对每个 PHP 文件最多只 extract 一次、读一次。

核心数据流
==========
build_all_chains(impact_payload, module_callers_payload, sink_evidence)
    -> list[list[node]]   # node 此时只是裸的 (file, function, line?, code?, role)

enrich_chains_with_pool(chains, slicer, pool)
    -> list[list[enriched_node]]
    -> enriched_node 含 function_ref（指向 pool）+ calls_next_at_line / calls_next_code

format_audit_pack(candidate, pool, *, max_chains_to_render=None)
    -> str   # markdown 风格 audit pack，给 Auditor 直接喂
"""

from __future__ import annotations

import asyncio
from collections import deque
import json
import os
import re
from pathlib import Path
from typing import Any

from app.agent.mcp import MCPToolbox

# ---------- 可调阈值 ----------
# 函数体最长行数；FunctionPool 内每个函数只存一份，开大点也不怕 token 爆。
SLICE_MAX_LINES = int(os.environ.get("CALLSCAN_SLICE_MAX_LINES", "120"))
# module 级 sink 抠 sink 行附近的代码窗口大小。
MODULE_SLICE_WINDOW = int(os.environ.get("CALLSCAN_MODULE_SLICE_WINDOW", "20"))

# Default caps keep large projects from exploding into thousands of chains per
# sink. Set the corresponding environment variable to 0 to disable a cap.
def _env_int(name: str, default: int | None = None) -> int | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
        return value if value > 0 else None
    except ValueError:
        return default


CHAIN_MAX_DEPTH = _env_int("CALLSCAN_MAX_CHAIN_DEPTH", 8)
BRANCH_LIMIT = _env_int("CALLSCAN_BRANCH_LIMIT", 16)
CHAINS_PER_SINK = _env_int("CALLSCAN_CHAINS_PER_SINK", 50)
# Auditor 默认每候选最多渲染多少条链（避免少数 sink 把 token 吃光）。
AUDIT_PACK_CHAINS = int(os.environ.get("CALLSCAN_AUDIT_PACK_CHAINS", "30"))
HELPER_DISCOVERY_DEPTH = int(os.environ.get("CALLSCAN_HELPER_DISCOVERY_DEPTH", "2"))
HELPER_DISCOVERY_LIMIT = int(os.environ.get("CALLSCAN_HELPER_DISCOVERY_LIMIT", "16"))

_LOCAL_CALL_RE = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_LOCAL_CALLBACK_RE = re.compile(r"[(,\[]\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?=[,\)])")
_HELPER_CALL_SKIP = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "function",
    "await",
    "new",
}


# ============================================================
# CodeSlicer：源码 + extract 缓存
# ============================================================
class CodeSlicer:
    def __init__(self, toolbox: MCPToolbox, project_root: Path):
        self._toolbox = toolbox
        self._project_root = project_root
        self._extract_cache: dict[str, asyncio.Future[Any]] = {}
        self._file_cache: dict[str, list[str]] = {}

    # ----- extract -----
    async def get_extract(self, rel_file: str) -> dict | None:
        if not rel_file:
            return None
        future = self._extract_cache.get(rel_file)
        if future is None:
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            self._extract_cache[rel_file] = future
            try:
                absolute = self._project_root / rel_file
                payload = await self._toolbox.call_tool(
                    "tldr__tldr_extract",
                    {
                        "file": str(absolute),
                        "base_path": str(self._project_root),
                    },
                )
                parsed = _parse_json_from_text(payload.get("text", ""))
                future.set_result(parsed if isinstance(parsed, dict) else None)
            except Exception as exc:  # noqa: BLE001
                future.set_exception(exc)
                raise
        return await future

    def seed_extract(self, rel_file: str, parsed: Any) -> None:
        if not rel_file or rel_file in self._extract_cache:
            return
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        future.set_result(parsed if isinstance(parsed, dict) else None)
        self._extract_cache[rel_file] = future

    async def get_function_info(
        self,
        rel_file: str,
        qualified_name: str | None,
    ) -> dict | None:
        """根据 'Class.method' 或 'function' 在 extract 里定位行号。"""
        if not qualified_name or qualified_name == "<module>":
            return None
        extract = await self.get_extract(rel_file)
        if not isinstance(extract, dict):
            return None
        if "." in qualified_name:
            class_name, method_name = qualified_name.split(".", 1)
            for class_info in extract.get("classes") or []:
                if class_info.get("name") != class_name:
                    continue
                for method in class_info.get("methods") or []:
                    if method.get("name") == method_name:
                        return {
                            "file": rel_file,
                            "function": qualified_name,
                            "line": method.get("line"),
                            "line_end": method.get("line_end"),
                            "class": class_name,
                        }
        else:
            for fn in extract.get("functions") or []:
                if fn.get("name") == qualified_name:
                    return {
                        "file": rel_file,
                        "function": qualified_name,
                        "line": fn.get("line"),
                        "line_end": fn.get("line_end"),
                        "class": None,
                    }
        return None

    # ----- 源码读取 -----
    def _read_file(self, rel_file: str) -> list[str]:
        if rel_file not in self._file_cache:
            try:
                text = (self._project_root / rel_file).read_text(
                    encoding="utf-8", errors="replace"
                )
                self._file_cache[rel_file] = text.splitlines()
            except OSError:
                self._file_cache[rel_file] = []
        return self._file_cache[rel_file]

    def slice_lines(
        self,
        rel_file: str,
        start: int | None,
        end: int | None,
        max_lines: int = SLICE_MAX_LINES,
    ) -> str | None:
        if not start or start <= 0:
            return None
        lines = self._read_file(rel_file)
        if not lines:
            return None
        if end is None or end <= 0:
            end = min(start + max_lines - 1, len(lines))
        else:
            end = min(end, len(lines))
        if end - start + 1 > max_lines:
            head_count = max_lines - 10
            head = lines[start - 1 : start - 1 + head_count]
            tail = lines[end - 9 : end]
            marker = f"// ... omitted {end - start + 1 - max_lines} line(s) ..."
            return "\n".join([*head, marker, *tail])
        return "\n".join(lines[start - 1 : end])

    def find_call_site(
        self,
        rel_file: str,
        fn_line: int | None,
        fn_line_end: int | None,
        callee_qualified: str,
    ) -> dict | None:
        if not callee_qualified or not fn_line:
            return None
        lines = self._read_file(rel_file)
        if not lines:
            return None
        end = fn_line_end or min(fn_line + SLICE_MAX_LINES, len(lines))
        end = min(end, len(lines))
        method = callee_qualified.rsplit(".", 1)[-1]
        if not method or method == "<module>":
            return None
        pattern = re.compile(rf"\b{re.escape(method)}\s*\(")
        for idx in range(fn_line - 1, end):
            line = lines[idx]
            if pattern.search(line):
                return {"line": idx + 1, "code": line.strip()[:240]}
        return None


# ============================================================
# FunctionPool：跨候选共享的源码池
# ============================================================
class FunctionPool:
    """key = "<rel_file>::<qualified_name>" 或 "<rel_file>::<module>@<line>" """

    MODULE_PREFIX = "<module>@"

    def __init__(self, slicer: CodeSlicer):
        self._slicer = slicer
        self._entries: dict[str, dict] = {}
        self._register_lock = asyncio.Lock()

    @staticmethod
    def function_key(rel_file: str, qualified_name: str) -> str:
        return f"{rel_file}::{qualified_name}"

    @staticmethod
    def module_key(rel_file: str, line: int) -> str:
        return f"{rel_file}::{FunctionPool.MODULE_PREFIX}{line}"

    async def register_function(
        self, rel_file: str, qualified_name: str
    ) -> str | None:
        if not rel_file or not qualified_name or qualified_name == "<module>":
            return None
        key = self.function_key(rel_file, qualified_name)
        if key in self._entries:
            return key
        info = await self._slicer.get_function_info(rel_file, qualified_name)
        if not info or not info.get("line"):
            return None
        slice_text = self._slicer.slice_lines(
            rel_file, info["line"], info.get("line_end")
        )
        async with self._register_lock:
            if key not in self._entries:
                self._entries[key] = {
                    "key": key,
                    "kind": "function",
                    "file": rel_file,
                    "function": qualified_name,
                    "line": info["line"],
                    "line_end": info.get("line_end"),
                    "code_slice": slice_text,
                }
        return key

    def register_module(self, rel_file: str, line: int) -> str | None:
        """登记 module 级节点的代码窗口（sink 行 ± MODULE_SLICE_WINDOW）。"""
        if not rel_file or not line or line <= 0:
            return None
        key = self.module_key(rel_file, line)
        if key in self._entries:
            return key
        start = max(1, line - MODULE_SLICE_WINDOW)
        end = line + MODULE_SLICE_WINDOW
        slice_text = self._slicer.slice_lines(
            rel_file,
            start,
            end,
            max_lines=MODULE_SLICE_WINDOW * 2 + 1,
        )
        if slice_text is None:
            return None
        self._entries[key] = {
            "key": key,
            "kind": "module",
            "file": rel_file,
            "function": "<module>",
            "line": start,
            "line_end": end,
            "anchor_line": line,
            "code_slice": slice_text,
        }
        return key

    def get(self, key: str | None) -> dict | None:
        return self._entries.get(key) if key else None

    def to_dict(self) -> dict[str, dict]:
        return self._entries

    def __len__(self) -> int:
        return len(self._entries)


# ============================================================
# 链构造：广度 + 深度全枚举
# ============================================================
def build_all_chains(
    impact_payload: dict[str, Any] | None,
    module_callers_payload: dict[str, Any] | None,
    sink_evidence: dict[str, Any],
    *,
    max_depth: int | None = CHAIN_MAX_DEPTH,
    branch_limit: int | None = BRANCH_LIMIT,
    max_chains: int | None = CHAINS_PER_SINK,
) -> list[list[dict[str, Any]]]:
    """枚举从 sink 反向到所有 entry point 的全部不同路径。

    默认无人为截断（max_depth/branch_limit/max_chains 都是 None），
    终止条件仅为 entry point / cycle / 源数据耗尽。
    """
    sink_file = sink_evidence["sink"]["file"]
    sink_function = sink_evidence["enclosing_symbol"]["function"]
    sink_line = (
        sink_evidence["enclosing_symbol"].get("line")
        or sink_evidence["sink"]["line"]
    )
    sink_node = {
        "role": "sink",
        "file": sink_file,
        "function": sink_function,
        "line": sink_line,
        "code": sink_evidence["sink"]["code"],
    }

    chains: list[list[dict[str, Any]]] = []

    parsed = (
        (impact_payload or {}).get("json")
        if isinstance(impact_payload, dict)
        else None
    )
    if isinstance(parsed, dict):
        for target in (parsed.get("targets") or {}).values():
            if not isinstance(target, dict):
                continue
            target_sink = dict(sink_node)
            target_sink["file"] = target.get("file") or sink_file
            target_sink["function"] = target.get("function") or sink_function
            top_callers = target.get("callers") or []
            if not top_callers:
                chains.append([target_sink])
                continue
            iter_callers = (
                top_callers[:branch_limit] if branch_limit else top_callers
            )
            for caller in iter_callers:
                if not isinstance(caller, dict):
                    continue
                _walk_all(
                    caller,
                    [_caller_node(caller)],
                    target_sink,
                    chains,
                    max_depth=max_depth,
                    branch_limit=branch_limit,
                )

    # module-level 反向：直接把每个 includer 当 entry。
    if isinstance(module_callers_payload, dict):
        for caller in module_callers_payload.get("callers") or []:
            if not isinstance(caller, dict):
                continue
            chains.append(
                [
                    {
                        "role": "caller",
                        "file": caller.get("file"),
                        "function": caller.get("function") or "<module>",
                        "line": caller.get("line"),
                        "code": caller.get("code"),
                    },
                    sink_node,
                ]
            )

    chains = _dedupe_chains(chains)
    if max_chains and len(chains) > max_chains:
        # 按链深度倒序保留更长的链（更接近 entry point 的更有意义）。
        chains.sort(key=lambda c: -len(c))
        chains = chains[:max_chains]
    return chains


def _caller_node(target: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": "caller",
        "file": target.get("file"),
        "function": target.get("function"),
        "line": None,
        "code": None,
    }


def _walk_all(
    node: dict[str, Any],
    path_from_sink: list[dict[str, Any]],
    sink_node: dict[str, Any],
    chains: list[list[dict[str, Any]]],
    *,
    max_depth: int | None,
    branch_limit: int | None,
) -> None:
    """反向 DFS。path_from_sink[0] 是直接 caller，[-1] 是当前节点。"""
    if max_depth and len(path_from_sink) >= max_depth:
        chains.append(list(reversed(path_from_sink)) + [sink_node])
        return

    note = (node.get("note") or "").lower()
    children = node.get("callers") or []

    if not children or "entry point" in note or "cycle" in note:
        chains.append(list(reversed(path_from_sink)) + [sink_node])
        return

    iter_children = children[:branch_limit] if branch_limit else children
    path_keys = {
        (n.get("file"), n.get("function")) for n in path_from_sink
    }

    for child in iter_children:
        if not isinstance(child, dict):
            continue
        identity = (child.get("file"), child.get("function"))
        if identity in path_keys:
            # 自环：把当前路径终结为一条 chain。
            chains.append(list(reversed(path_from_sink)) + [sink_node])
            continue
        _walk_all(
            child,
            path_from_sink + [_caller_node(child)],
            sink_node,
            chains,
            max_depth=max_depth,
            branch_limit=branch_limit,
        )


def _dedupe_chains(
    chains: list[list[dict[str, Any]]],
) -> list[list[dict[str, Any]]]:
    unique: list[list[dict[str, Any]]] = []
    seen: set[tuple] = set()
    for chain in chains:
        if not chain:
            continue
        key = tuple(
            (n.get("file"), n.get("function"), n.get("line")) for n in chain
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(chain)
    return unique


# ============================================================
# enrich：把链节点替换为 function_ref，全程通过 pool
# ============================================================
async def enrich_chains_with_pool(
    chains: list[list[dict[str, Any]]],
    slicer: CodeSlicer,
    pool: FunctionPool,
) -> list[list[dict[str, Any]]]:
    """把链节点的源码替换为对全局 FunctionPool 的引用。

    输出节点字段：
      role, function, file, function_ref, line, line_end,
      calls_next_at_line, calls_next_code,
      sink_line, sink_code (仅 sink 节点)
    """
    # 1) 收集所有需要 register 的函数（去重），并行注册。
    function_refs: set[tuple[str, str]] = set()
    module_refs: set[tuple[str, int]] = set()
    for chain in chains:
        for node in chain:
            fn = node.get("function")
            file = node.get("file") or ""
            if fn and fn != "<module>" and file:
                function_refs.add((file, fn))
            elif fn == "<module>" and file and node.get("line"):
                module_refs.add((file, int(node["line"])))

    if function_refs:
        await asyncio.gather(
            *(pool.register_function(f, fn) for f, fn in function_refs),
            return_exceptions=True,
        )
    for file, line in module_refs:
        pool.register_module(file, line)

    # 2) 遍历链拼装 enriched node。
    out: list[list[dict[str, Any]]] = []
    for chain in chains:
        new_chain: list[dict[str, Any]] = []
        for idx, node in enumerate(chain):
            file = node.get("file") or ""
            fn = node.get("function") or ""
            ref: str | None = None
            entry: dict | None = None

            if fn and fn != "<module>" and file:
                ref = FunctionPool.function_key(file, fn)
                entry = pool.get(ref)
                if entry is None:
                    ref = None
            elif fn == "<module>" and file and node.get("line"):
                ref = FunctionPool.module_key(file, int(node["line"]))
                entry = pool.get(ref)
                if entry is None:
                    ref = None

            new_node: dict[str, Any] = {
                "role": node.get("role"),
                "function": fn,
                "file": file,
                "function_ref": ref,
                "line": (entry["line"] if entry else node.get("line")),
                "line_end": (entry["line_end"] if entry else None),
            }

            if node.get("role") == "sink":
                new_node["sink_line"] = node.get("line")
                new_node["sink_code"] = node.get("code")

            # 找出当前 caller 调用下一跳的具体行号。
            if node.get("role") == "caller" and idx + 1 < len(chain):
                callee = chain[idx + 1].get("function") or ""
                if entry and entry.get("line"):
                    site = slicer.find_call_site(
                        file,
                        entry["line"],
                        entry.get("line_end"),
                        callee,
                    )
                    if site:
                        new_node["calls_next_at_line"] = site["line"]
                        new_node["calls_next_code"] = site["code"]
                # module-level caller：节点自带的 line 就是 include 行。
                elif node.get("line"):
                    new_node["calls_next_at_line"] = node.get("line")
                    new_node["calls_next_code"] = node.get("code")

            new_chain.append(new_node)
        out.append(new_chain)
    return out


async def enrich_chains_static_fast(
    chains: list[list[dict[str, Any]]],
    pool: FunctionPool,
) -> list[list[dict[str, Any]]]:
    """静态模式轻量 enrich：只登记 module 窗口，不做 call-site 扫描。"""
    out: list[list[dict[str, Any]]] = []
    for chain in chains:
        new_chain: list[dict[str, Any]] = []
        for node in chain:
            file = node.get("file") or ""
            fn = node.get("function") or ""
            ref: str | None = None
            line = node.get("line")
            if fn == "<module>" and file and line:
                ref = pool.register_module(file, int(line))
            new_chain.append(
                {
                    "role": node.get("role"),
                    "function": fn,
                    "file": file,
                    "function_ref": ref,
                    "line": line,
                    "line_end": node.get("line_end"),
                    "sink_line": node.get("sink_line") or node.get("line"),
                    "sink_code": node.get("sink_code") or node.get("code"),
                    "code": node.get("code"),
                }
            )
        out.append(new_chain)
    return out


async def collect_local_helper_refs(
    chains: list[list[dict[str, Any]]],
    slicer: CodeSlicer,
    pool: FunctionPool,
    *,
    max_depth: int = HELPER_DISCOVERY_DEPTH,
    max_helpers: int = HELPER_DISCOVERY_LIMIT,
) -> list[str]:
    """Discover same-file helper functions referenced by candidate bodies.

    This is primarily used for XSS-style sinks where the vulnerability verdict
    depends on helper implementations such as `escapeHtml`, `renderMarkdown`,
    `articleCard`, or `compactArticle`.
    """

    queue: deque[tuple[str, int]] = deque()
    seen_refs: set[str] = set()
    helper_refs: list[str] = []

    for chain in chains:
        for node in chain:
            if node.get("role") != "sink":
                continue
            ref = node.get("function_ref")
            if ref and ref not in seen_refs:
                seen_refs.add(ref)
                queue.append((ref, 0))

    while queue and len(helper_refs) < max_helpers:
        ref, depth = queue.popleft()
        entry = pool.get(ref)
        if not entry or entry.get("kind") != "function":
            continue
        rel_file = entry.get("file") or ""
        current_name = entry.get("function") or ""
        extract = await slicer.get_extract(rel_file)
        available = _available_local_functions(extract)
        if not available:
            continue
        for helper_name in _called_local_helpers(
            entry.get("code_slice") or "",
            available,
            current_name=current_name,
        ):
            helper_ref = await pool.register_function(rel_file, helper_name)
            if not helper_ref or helper_ref in seen_refs:
                continue
            seen_refs.add(helper_ref)
            helper_refs.append(helper_ref)
            if depth + 1 < max_depth:
                queue.append((helper_ref, depth + 1))
            if len(helper_refs) >= max_helpers:
                break

    return helper_refs


def _available_local_functions(extract: dict[str, Any] | None) -> set[str]:
    if not isinstance(extract, dict):
        return set()
    names: set[str] = set()
    for function in extract.get("functions") or []:
        name = function.get("name")
        if isinstance(name, str) and name:
            names.add(name)
    return names


def _called_local_helpers(
    code_slice: str,
    available: set[str],
    *,
    current_name: str,
) -> list[str]:
    if not code_slice or not available:
        return []
    results: list[str] = []
    seen: set[str] = set()
    for pattern in (_LOCAL_CALL_RE, _LOCAL_CALLBACK_RE):
        for match in pattern.finditer(code_slice):
            name = match.group(1)
            if name in _HELPER_CALL_SKIP or name == current_name:
                continue
            if name not in available or name in seen:
                continue
            seen.add(name)
            results.append(name)
    return results


# ============================================================
# Audit pack：候选内去重的 markdown 渲染
# ============================================================
def _format_tldr_extract_section(
    extract_json: dict[str, Any] | None,
    symbol: dict[str, Any] | None,
) -> str:
    """Render a focused tldr_extract snapshot (already fetched during CallScan)."""
    if not isinstance(extract_json, dict):
        return ""
    lines: list[str] = ["## File extract (tldr_extract)"]
    file_path = extract_json.get("file_path") or (symbol or {}).get("file") or "?"
    lines.append(
        f"file: {file_path}  language: {extract_json.get('language') or '?'}"
    )
    imports = extract_json.get("imports") or []
    if imports:
        names = []
        for item in imports[:24]:
            if isinstance(item, dict):
                names.append(str(item.get("module") or item))
            else:
                names.append(str(item))
        lines.append("imports: " + ", ".join(names))
    fn_name = (symbol or {}).get("function") or ""
    if fn_name and fn_name != "<module>":
        if "." in fn_name:
            class_name, method_name = fn_name.split(".", 1)
            for class_info in extract_json.get("classes") or []:
                if class_info.get("name") != class_name:
                    continue
                methods = [
                    m
                    for m in (class_info.get("methods") or [])
                    if m.get("name") == method_name
                ]
                payload = {
                    "class": class_name,
                    "line": class_info.get("line"),
                    "methods": methods or (class_info.get("methods") or [])[:3],
                }
                lines.append("```json")
                lines.append(json.dumps(payload, ensure_ascii=False, indent=2))
                lines.append("```")
                break
        else:
            for function in extract_json.get("functions") or []:
                if function.get("name") == fn_name:
                    lines.append("```json")
                    lines.append(json.dumps(function, ensure_ascii=False, indent=2))
                    lines.append("```")
                    break
    call_graph = extract_json.get("call_graph")
    if isinstance(call_graph, dict) and call_graph:
        lines.append("call_graph (truncated):")
        lines.append("```json")
        lines.append(
            json.dumps(call_graph, ensure_ascii=False, indent=2)[:4000]
        )
        lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _format_sink_function_window(
    *,
    sink: dict[str, Any],
    symbol: dict[str, Any] | None,
    window_text: str | None,
    language: Any,
) -> str:
    if not window_text:
        return ""
    fn_name = (symbol or {}).get("function") or "?"
    sink_file = sink.get("file") or "?"
    sink_line = sink.get("line") or "?"
    lines = [
        "## Sink function context (±20 lines)",
        f"enclosing: {fn_name} @ {sink_file}:{sink_line}",
        f"```{_code_fence_language(language)}",
        window_text.rstrip(),
        "```",
        "",
    ]
    return "\n".join(lines)


def _format_direct_caller_section(
    chains: list[list[dict[str, Any]]],
    pool: "FunctionPool",
) -> str:
    if not chains:
        return ""
    chain = chains[0]
    if len(chain) < 2:
        return ""
    caller = chain[-2]
    lines = ["## Direct caller (1-hop)"]
    lines.append(
        f"caller: {caller.get('function') or '?'} @ {caller.get('file') or '?'}"
    )
    if caller.get("calls_next_at_line"):
        lines.append(
            f"call site line {caller['calls_next_at_line']}: "
            f"{(caller.get('calls_next_code') or '').strip()}"
        )
    ref = caller.get("function_ref")
    if ref:
        entry = pool.get(ref)
        if entry and entry.get("code_slice"):
            header = entry.get("function") or caller.get("function") or "?"
            loc = entry.get("file") or caller.get("file") or "?"
            lines.append(f"caller body ({header} @ {loc}):")
            lines.append("```")
            lines.append(str(entry.get("code_slice") or "").rstrip())
            lines.append("```")
    lines.append("")
    return "\n".join(lines)


def format_audit_pack(
    candidate: dict[str, Any],
    pool: FunctionPool,
    *,
    max_chains_to_render: int | None = AUDIT_PACK_CHAINS,
    include_bodies: bool = True,
    extract_json: dict[str, Any] | None = None,
    enclosing_symbol: dict[str, Any] | None = None,
    sink_function_window: str | None = None,
) -> str:
    """渲染单个候选为 Auditor 的输入 pack。

    候选内函数体只出现一次：先列每条链的路径 + 跳转点代码，再附一份
    "Function bodies" 章节，每个函数 only-once。
    """
    sink_rule = candidate.get("sink_rule") or {}
    sink = candidate.get("sink") or {}
    all_chains = candidate.get("call_chains") or []
    chains = (
        all_chains[:max_chains_to_render]
        if max_chains_to_render
        else list(all_chains)
    )

    lines: list[str] = []
    lines.append(
        f"# Sink: {sink_rule.get('function', '?')} "
        f"@ {sink.get('file')}:{sink.get('line')}"
    )
    lines.append(
        "severity={severity} / vulnerability={vuln} / language={lang}".format(
            severity=sink_rule.get("severity") or "?",
            vuln=candidate.get("vulnerability_type") or "?",
            lang=candidate.get("language") or "?",
        )
    )
    if sink_rule.get("level") or sink_rule.get("semantic_tags") or sink_rule.get("required_evidence"):
        lines.append("")
        lines.append("## Sink semantic profile")
        lines.append(f"- level: {sink_rule.get('level') or 'L0'}")
        if sink_rule.get("semantic_tags"):
            lines.append(f"- semantic_tags: {', '.join(sink_rule.get('semantic_tags') or [])}")
        if sink_rule.get("required_evidence"):
            lines.append(f"- required_evidence: {', '.join(sink_rule.get('required_evidence') or [])}")
        if sink_rule.get("repair_hints"):
            lines.append(f"- repair_hints: {', '.join(sink_rule.get('repair_hints') or [])}")
    sink_code = (sink.get("code") or "").strip()
    if sink_code:
        lines.append(f"sink line: {sink_code}")
    lines.append("")

    symbol = enclosing_symbol or candidate.get("enclosing_symbol")
    extract_block = _format_tldr_extract_section(
        extract_json or candidate.get("tldr_extract_json"),
        symbol if isinstance(symbol, dict) else None,
    )
    if extract_block:
        lines.append(extract_block)

    window_block = _format_sink_function_window(
        sink=sink,
        symbol=symbol if isinstance(symbol, dict) else None,
        window_text=sink_function_window or candidate.get("sink_function_window"),
        language=candidate.get("language"),
    )
    if window_block:
        lines.append(window_block)

    caller_block = _format_direct_caller_section(chains, pool)
    if caller_block:
        lines.append(caller_block)

    # ----- chains overview -----
    lines.append(
        f"## Call chains  ({len(chains)} of {len(all_chains)} shown)"
    )
    for idx, chain in enumerate(chains, 1):
        path = " -> ".join(node.get("function") or "?" for node in chain)
        lines.append(f"{idx}. {path}")
        for node in chain[:-1]:
            if node.get("calls_next_at_line"):
                fn = node.get("function") or "?"
                lines.append(
                    f"   {fn} line {node['calls_next_at_line']}: "
                    f"{(node.get('calls_next_code') or '').strip()}"
                )
    lines.append("")

    # ----- 候选内函数体去重 -----
    seen_keys: list[str] = []
    seen_set: set[str] = set()
    for chain in chains:
        for node in chain:
            key = node.get("function_ref")
            if key and key not in seen_set:
                seen_keys.append(key)
                seen_set.add(key)

    helper_keys = []
    for key in candidate.get("helper_function_refs") or []:
        if key and key not in seen_set:
            helper_keys.append(key)
            seen_set.add(key)

    if seen_keys and include_bodies:
        lines.append("## Function bodies (deduped within candidate)")
        for key in seen_keys:
            entry = pool.get(key)
            if not entry:
                continue
            anchor = entry.get("anchor_line")
            header_loc = entry["file"]
            if entry.get("line"):
                header_loc += f":{entry['line']}-{entry.get('line_end','?')}"
            if entry.get("kind") == "module":
                lines.append(
                    f"### <module> @ {header_loc}"
                    + (f"  (sink near line {anchor})" if anchor else "")
                )
            else:
                lines.append(f"### {entry['function']}  ({header_loc})")
            lines.append(f"```{_code_fence_language(candidate.get('language'))}")
            lines.append(entry.get("code_slice") or "")
            lines.append("```")
            lines.append("")
    if helper_keys and include_bodies:
        lines.append("## Local helper bodies")
        for key in helper_keys:
            entry = pool.get(key)
            if not entry:
                continue
            header_loc = entry["file"]
            if entry.get("line"):
                header_loc += f":{entry['line']}-{entry.get('line_end','?')}"
            lines.append(f"### {entry['function']}  ({header_loc})")
            lines.append(f"```{_code_fence_language(candidate.get('language'))}")
            lines.append(entry.get("code_slice") or "")
            lines.append("```")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _code_fence_language(language: Any) -> str:
    if not isinstance(language, str) or not language:
        return "text"
    return {
        "javascript": "javascript",
        "typescript": "typescript",
        "python": "python",
        "php": "php",
        "java": "java",
        "go": "go",
        "rust": "rust",
        "c": "c",
        "cpp": "cpp",
        "html": "html",
    }.get(language, "text")


# ============================================================
# 工具
# ============================================================
def _parse_json_from_text(text: str) -> Any:
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:].strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(stripped[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None

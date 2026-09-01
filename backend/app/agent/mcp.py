"""MCP client helpers for long-lived stdio tool sessions."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Without a timeout a single tldr_impact on a large repo can block the whole scan.
MCP_TOOL_TIMEOUT_S = float(os.environ.get("MCP_TOOL_TIMEOUT", "120"))


@dataclass(frozen=True)
class MCPServerSpec:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    cwd: str | Path | None = None


@dataclass(frozen=True)
class MCPToolRef:
    server_name: str
    tool_name: str


class _MCPSlot:
    """One independent MCP subprocess group (tldr + ripgrep).

    Stdio sessions are entered against the *toolbox's* shared AsyncExitStack
    so that all subprocess cancel scopes pop in LIFO order on the owning task.
    Per-server locks inside the slot prevent JSON-RPC frames from interleaving
    on the same stdin.
    """

    def __init__(self, server_specs: list[MCPServerSpec]) -> None:
        self._server_specs = server_specs
        self._sessions: dict[str, ClientSession] = {}
        self._locks: dict[str, Any] = {}
        self._tools: dict[str, dict[str, Any]] = {}
        self._tool_refs: dict[str, MCPToolRef] = {}

    async def start(self, stack: AsyncExitStack) -> None:
        import asyncio

        for spec in self._server_specs:
            params = StdioServerParameters(
                command=spec.command,
                args=spec.args,
                env=spec.env,
                cwd=spec.cwd,
                encoding_error_handler="replace",
            )
            errlog = stack.enter_context(open(os.devnull, "w", encoding="utf-8"))
            read, write = await stack.enter_async_context(
                stdio_client(params, errlog=errlog)
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()

            self._sessions[spec.name] = session
            self._locks[spec.name] = asyncio.Lock()

            tools = await session.list_tools()
            for tool in tools.tools:
                tool_data = _dump_mcp_model(tool)
                tool_name = tool_data["name"]
                namespaced_name = namespaced_tool_name(spec.name, tool_name)
                self._tools[namespaced_name] = {
                    "name": namespaced_name,
                    "description": f"[{spec.name}] {tool_data.get('description', '')}",
                    "input_schema": tool_data.get("inputSchema")
                    or tool_data.get("input_schema")
                    or {"type": "object", "properties": {}},
                }
                self._tool_refs[namespaced_name] = MCPToolRef(spec.name, tool_name)

    @property
    def tool_names(self) -> list[str]:
        return sorted(self._tools)

    def as_litellm_tools(self, allowed_names: set[str] | None = None) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool["description"],
                    "parameters": tool["input_schema"],
                },
            }
            for name, tool in sorted(self._tools.items())
            if allowed_names is None or name in allowed_names
        ]

    def as_json_tool_catalog(self, allowed_names: set[str] | None = None) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "description": tool["description"],
                "parameters": tool["input_schema"],
            }
            for name, tool in sorted(self._tools.items())
            if allowed_names is None or name in allowed_names
        ]

    async def call_tool(
        self, namespaced_name: str, arguments: dict[str, Any] | None
    ) -> dict[str, Any]:
        if namespaced_name not in self._tool_refs:
            return {
                "tool": namespaced_name,
                "is_error": True,
                "text": f"Unknown MCP tool: {namespaced_name}",
            }

        ref = self._tool_refs[namespaced_name]
        session = self._sessions[ref.server_name]
        lock = self._locks[ref.server_name]

        async with lock:
            try:
                result = await session.call_tool(
                    ref.tool_name,
                    arguments or {},
                    read_timeout_seconds=timedelta(seconds=MCP_TOOL_TIMEOUT_S),
                )
            except asyncio.TimeoutError:
                return {
                    "tool": namespaced_name,
                    "server": ref.server_name,
                    "name": ref.tool_name,
                    "is_error": True,
                    "content": [],
                    "text": (
                        f"MCP tool timed out after {MCP_TOOL_TIMEOUT_S:.0f}s "
                        f"({ref.tool_name}). Narrow the query or retry."
                    ),
                }
            except Exception as exc:  # noqa: BLE001
                # Defensive: never let a single MCP RPC failure crash the whole
                # toolbox. Surface as is_error=True so callers (LLM tool-loop /
                # CallScan analyse_hit) can move on rather than abort the agent.
                return {
                    "tool": namespaced_name,
                    "server": ref.server_name,
                    "name": ref.tool_name,
                    "is_error": True,
                    "content": [],
                    "text": (
                        f"MCP tool error ({type(exc).__name__}): {exc}"
                    ),
                }

        return {
            "tool": namespaced_name,
            "server": ref.server_name,
            "name": ref.tool_name,
            "is_error": _mcp_is_error(result),
            "content": _mcp_content(result),
            "text": _mcp_text(result),
        }


class MCPToolbox:
    """Owns one or more MCP subprocess pools and exposes namespaced tools.

    ``pool_size`` controls how many independent tldr-mcp processes are spawned.
    CallScan routes tool calls by ``(path, language)`` hash so parallel sinks
    on the same language share one warm call-graph cache per slot.
    """

    def __init__(self, server_specs: list[MCPServerSpec], *, pool_size: int = 1) -> None:
        self._server_specs = server_specs
        self._pool_size = max(1, min(int(pool_size), 16))
        self._slots: list[_MCPSlot] = []
        self._stack = AsyncExitStack()

    async def __aenter__(self) -> "MCPToolbox":
        await self._stack.__aenter__()
        try:
            for _ in range(self._pool_size):
                slot = _MCPSlot(self._server_specs)
                await slot.start(self._stack)
                self._slots.append(slot)
        except BaseException:
            await self._stack.__aexit__(*_sys_exc_info_or_none())
            raise
        return self

    async def __aexit__(self, exc_type, exc, tb):
        try:
            return await self._stack.__aexit__(exc_type, exc, tb)
        finally:
            self._slots.clear()

    @property
    def pool_size(self) -> int:
        return len(self._slots) or self._pool_size

    @property
    def tool_names(self) -> list[str]:
        if not self._slots:
            return []
        return self._slots[0].tool_names

    def as_litellm_tools(self, allowed_names: set[str] | None = None) -> list[dict[str, Any]]:
        if not self._slots:
            return []
        return self._slots[0].as_litellm_tools(allowed_names)

    def as_json_tool_catalog(self, allowed_names: set[str] | None = None) -> list[dict[str, Any]]:
        if not self._slots:
            return []
        return self._slots[0].as_json_tool_catalog(allowed_names)

    def _route_slot(self, namespaced_name: str, arguments: dict[str, Any] | None) -> int:
        if len(self._slots) <= 1:
            return 0
        args = arguments or {}
        path = str(args.get("path") or args.get("file") or "")
        language = str(args.get("language") or "")
        route_key = f"{namespaced_name}:{path}:{language}"
        digest = hashlib.md5(route_key.encode("utf-8")).hexdigest()
        return int(digest[:8], 16) % len(self._slots)

    async def call_tool(
        self, namespaced_name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if not self._slots:
            return {
                "tool": namespaced_name,
                "is_error": True,
                "text": "MCP toolbox not started",
            }
        slot_idx = self._route_slot(namespaced_name, arguments)
        return await self._slots[slot_idx].call_tool(namespaced_name, arguments)


def _sys_exc_info_or_none():
    exc_type, exc, tb = sys.exc_info()
    return (exc_type, exc, tb) if exc_type is not None else (None, None, None)


def namespaced_tool_name(server_name: str, tool_name: str) -> str:
    return f"{server_name}__{tool_name}"


def default_server_specs(cwd: str | Path | None = None) -> list[MCPServerSpec]:
    tldr_exe = PROJECT_ROOT / "MCP" / "tldr-code" / "target" / "release" / "tldr-mcp.exe"
    rg_dir = PROJECT_ROOT / "ripgrep"
    server_cwd = Path(cwd) if cwd is not None else PROJECT_ROOT

    if not tldr_exe.is_file():
        raise FileNotFoundError(f"tldr MCP executable not found: {tldr_exe}")

    env = os.environ.copy()
    if rg_dir.is_dir():
        env["PATH"] = str(rg_dir) + os.pathsep + env.get("PATH", "")

    return [
        MCPServerSpec(name="tldr", command=str(tldr_exe), args=[], cwd=server_cwd),
        MCPServerSpec(
            name="ripgrep",
            command="npx",
            args=["-y", "mcp-ripgrep@latest"],
            env=env,
            cwd=server_cwd,
        ),
    ]


def _dump_mcp_model(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True, exclude_none=True)
    if isinstance(value, dict):
        return value
    return dict(value)


def _mcp_is_error(result: Any) -> bool:
    if hasattr(result, "isError"):
        return bool(result.isError)
    if hasattr(result, "is_error"):
        return bool(result.is_error)
    return False


def _mcp_content(result: Any) -> list[dict[str, Any]]:
    content = getattr(result, "content", None) or []
    items: list[dict[str, Any]] = []
    for item in content:
        if hasattr(item, "model_dump"):
            items.append(item.model_dump(by_alias=True, exclude_none=True))
        elif isinstance(item, dict):
            items.append(item)
        elif hasattr(item, "text"):
            items.append({"type": getattr(item, "type", "text"), "text": item.text})
        else:
            items.append({"type": "unknown", "text": str(item)})
    return items


def _mcp_text(result: Any) -> str:
    parts = []
    for item in _mcp_content(result):
        text = item.get("text")
        if text is not None:
            parts.append(str(text))
        elif item:
            parts.append(str(item))
    return "\n".join(parts)

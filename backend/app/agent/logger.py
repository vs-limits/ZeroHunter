"""LLM 对话日志 + 项目级可观测性。

设计目标：
1. 仍兼容原行为：每次 chat_completion 落盘到 <repo_root>/logs/YY-MM-DD.log。
2. 新增 **项目级落盘**：每次进入 sub-agent 时由 runner 注入
   ``observability scope``，logger 把对话和事件同时写到
   ``<artifacts_dir>/conversations/<agent>/turn-NNNN.json`` 与
   ``<artifacts_dir>/events.jsonl``。
   方便管理平台按 run / agent 维度复盘。
3. 兼容并发：用 ContextVar 跟踪当前 agent / scope，runner 设置后所有
   下游 LLM 调用自动归属。
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# 仓库根：backend/app/agent/logger.py -> parents[3]
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_LOG_DIR = _PROJECT_ROOT / "logs"

# ---------- ContextVars ----------

_current_role: ContextVar[str | None] = ContextVar("dm_agent_role", default=None)
_current_scope: ContextVar["ObsScope | None"] = ContextVar("dm_obs_scope", default=None)

# 全局锁
_write_lock = threading.Lock()
_MAX_LOG_TEXT_CHARS = 4000
_MAX_LOG_LIST_ITEMS = 20


@dataclass
class ObsScope:
    """运行级可观测性上下文。

    每次 ``run_agent`` 调用前，runner 会构造一个 ObsScope 并注入。
    LLM 客户端落盘时即可拿到 artifacts_dir / agent / turn 信息。
    """

    project_path: str
    project_root: Path
    artifacts_dir: Path
    mode: str = "project"  # "project" / "specific"
    run_id: str | None = None
    target_rel_dir: str | None = None
    agent: str | None = None
    # 每个 (agent) 的轮次计数器
    turn_counters: dict[str, int] = field(default_factory=dict)
    # 这一次 run_agent 顶层会话的 session_id（区分同一 agent 的不同 run）
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    started_at: float = field(default_factory=time.time)

    @property
    def conversations_dir(self) -> Path:
        return self.artifacts_dir / "conversations"

    @property
    def events_path(self) -> Path:
        return self.artifacts_dir / "events.jsonl"

    def next_turn(self, agent: str) -> int:
        n = self.turn_counters.get(agent, 0) + 1
        self.turn_counters[agent] = n
        return n

    def turn_dir(self, agent: str) -> Path:
        return self.conversations_dir / agent

    def index_path(self, agent: str) -> Path:
        return self.turn_dir(agent) / "index.jsonl"

    def turn_path(self, agent: str, turn: int) -> Path:
        return self.turn_dir(agent) / f"turn-{turn:04d}.json"

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "project_root": str(self.project_root),
            "artifacts_dir": str(self.artifacts_dir),
            "mode": self.mode,
            "run_id": self.run_id,
            "target_rel_dir": self.target_rel_dir,
            "session_id": self.session_id,
        }


# ---------- 公共 API ----------


def set_agent_role(role: str | None) -> object:
    return _current_role.set(role)


def reset_agent_role(token: object) -> None:
    try:
        _current_role.reset(token)  # type: ignore[arg-type]
    except (LookupError, ValueError):
        pass


def get_agent_role() -> str | None:
    return _current_role.get()


def set_obs_scope(scope: ObsScope | None) -> object:
    return _current_scope.set(scope)


def reset_obs_scope(token: object) -> None:
    try:
        _current_scope.reset(token)  # type: ignore[arg-type]
    except (LookupError, ValueError):
        pass


def get_obs_scope() -> ObsScope | None:
    return _current_scope.get()


# ---------- 全局日志（向后兼容） ----------


def _log_path() -> Path:
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    filename = datetime.now().strftime("%y-%m-%d") + ".log"
    return _LOG_DIR / filename


def _write_global_entry(entry: dict[str, Any]) -> None:
    try:
        line = json.dumps(entry, ensure_ascii=False, default=_json_default)
    except Exception as serialize_error:  # pragma: no cover
        line = json.dumps(
            {
                "ts": entry.get("ts"),
                "type": entry.get("type"),
                "agent": entry.get("agent"),
                "serialize_error": repr(serialize_error),
            },
            ensure_ascii=False,
        )
    path = _log_path()
    with _write_lock:
        with path.open("a", encoding="utf-8") as fp:
            fp.write(line)
            fp.write("\n")


# ---------- 项目级落盘 ----------


def _write_jsonl(path: Path, entry: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False, default=_json_default)
    with _write_lock:
        with path.open("a", encoding="utf-8") as fp:
            fp.write(line)
            fp.write("\n")


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2, default=_json_default)
    with _write_lock:
        path.write_text(text + "\n", encoding="utf-8")


def write_event(event_type: str, **payload: Any) -> None:
    """写 events.jsonl，给前端工作流图实时驱动状态。"""
    scope = get_obs_scope()
    if scope is None:
        return
    entry = {
        "ts": _now_iso(),
        "type": event_type,
        "agent": payload.pop("agent", get_agent_role()),
        "session_id": scope.session_id,
        "run_id": scope.run_id,
        **payload,
    }
    _write_jsonl(scope.events_path, entry)


# ---------- LLM 请求/响应（同时写全局 + 项目级） ----------


def log_request(
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
    tool_choice: Any,
    temperature: float,
    max_tokens: int,
) -> None:
    role = get_agent_role()
    sanitized_messages = _sanitize_for_log(messages)
    request_brief = {
        "ts": _now_iso(),
        "type": "llm_request",
        "agent": role,
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "tool_choice": tool_choice,
        "tools": _summarize_tools(tools),
        "messages": sanitized_messages,
    }
    _write_global_entry(request_brief)

    scope = get_obs_scope()
    if scope is None or role is None:
        return
    turn = scope.next_turn(role)
    _PENDING_TURN.set((role, turn))
    full_request = {
        "session_id": scope.session_id,
        "agent": role,
        "turn": turn,
        "ts": _now_iso(),
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "tool_choice": tool_choice,
        "tools": tools,
        "messages": messages,  # 原文落盘
    }
    _write_json(scope.turn_path(role, turn), {"request": full_request})

    # index 先写一条占位（status=pending），response 来了再追加更新
    _write_jsonl(
        scope.index_path(role),
        {
            "turn": turn,
            "ts": full_request["ts"],
            "agent": role,
            "model": model,
            "messages_count": len(messages),
            "tools_count": (tools or []) and len(tools or []),
            "status": "pending",
        },
    )

    write_event(
        "llm_request",
        agent=role,
        turn=turn,
        model=model,
        messages_count=len(messages),
        tools_count=len(tools) if tools else 0,
    )


# 当前协程"还没收到 response 的那个 turn"
_PENDING_TURN: ContextVar[tuple[str, int] | None] = ContextVar("dm_pending_turn", default=None)


def log_response(*, model: str, response: Any) -> None:
    role = get_agent_role()
    coerced = _coerce_response(response)
    _write_global_entry(
        {
            "ts": _now_iso(),
            "type": "llm_response",
            "agent": role,
            "model": model,
            "response": coerced,
        }
    )

    scope = get_obs_scope()
    pending = _PENDING_TURN.get()
    if scope is None or pending is None:
        return
    pending_role, turn = pending
    if role and role != pending_role:
        # 角色发生切换（不太常见），用 pending 里记录的为准
        role = pending_role

    # 把整轮（请求 + 响应）合并写一份完整文件
    turn_path = scope.turn_path(role, turn)
    existing: dict[str, Any] = {}
    if turn_path.is_file():
        try:
            existing = json.loads(turn_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {}
    existing["response"] = {
        "ts": _now_iso(),
        "model": model,
        "raw": _full_response(response),
    }
    _write_json(turn_path, existing)

    # 写一条 index 收尾记录
    usage = _extract_usage(response)
    finish_reason = _extract_finish_reason(response)
    has_tool_calls = _has_tool_calls(response)
    _write_jsonl(
        scope.index_path(role),
        {
            "turn": turn,
            "ts": _now_iso(),
            "agent": role,
            "model": model,
            "status": "ok",
            "finish_reason": finish_reason,
            "has_tool_calls": has_tool_calls,
            "usage": usage,
        },
    )

    write_event(
        "llm_response",
        agent=role,
        turn=turn,
        model=model,
        finish_reason=finish_reason,
        has_tool_calls=has_tool_calls,
        usage=usage,
    )

    _PENDING_TURN.set(None)


def log_error(*, model: str, error: BaseException) -> None:
    role = get_agent_role()
    _write_global_entry(
        {
            "ts": _now_iso(),
            "type": "llm_error",
            "agent": role,
            "model": model,
            "error_type": type(error).__name__,
            "error": str(error),
        }
    )
    scope = get_obs_scope()
    pending = _PENDING_TURN.get()
    if scope is None or pending is None:
        return
    pending_role, turn = pending
    role = pending_role
    turn_path = scope.turn_path(role, turn)
    existing: dict[str, Any] = {}
    if turn_path.is_file():
        try:
            existing = json.loads(turn_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {}
    existing["error"] = {
        "ts": _now_iso(),
        "model": model,
        "error_type": type(error).__name__,
        "error": str(error),
    }
    _write_json(turn_path, existing)
    _write_jsonl(
        scope.index_path(role),
        {
            "turn": turn,
            "ts": _now_iso(),
            "agent": role,
            "model": model,
            "status": "error",
            "error_type": type(error).__name__,
            "error": str(error),
        },
    )
    write_event(
        "llm_error",
        agent=role,
        turn=turn,
        model=model,
        error_type=type(error).__name__,
        error=str(error),
    )
    _PENDING_TURN.set(None)


# ---------- 序列化辅助 ----------


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="milliseconds")


def _json_default(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump(exclude_none=True)
        except Exception:  # pragma: no cover
            return str(value)
    if isinstance(value, (set, tuple)):
        return list(value)
    if isinstance(value, Path):
        return str(value)
    return str(value)


def _coerce_response(response: Any) -> Any:
    if response is None:
        return None
    if hasattr(response, "model_dump"):
        try:
            return _sanitize_for_log(response.model_dump(exclude_none=True))
        except Exception:  # pragma: no cover
            return str(response)
    if isinstance(response, dict):
        return _sanitize_for_log(response)
    if hasattr(response, "to_dict"):
        try:
            return _sanitize_for_log(response.to_dict())
        except Exception:  # pragma: no cover
            return str(response)
    return str(response)


def _full_response(response: Any) -> Any:
    """全量落盘：不截断。"""
    if response is None:
        return None
    if hasattr(response, "model_dump"):
        try:
            return response.model_dump(exclude_none=True)
        except Exception:
            return str(response)
    if isinstance(response, dict):
        return response
    if hasattr(response, "to_dict"):
        try:
            return response.to_dict()
        except Exception:
            return str(response)
    return str(response)


def _summarize_tools(tools: list[dict[str, Any]] | None) -> Any:
    if tools is None:
        return None
    names = []
    for tool in tools:
        function = tool.get("function") if isinstance(tool, dict) else None
        if isinstance(function, dict):
            names.append(function.get("name"))
        else:
            names.append(str(tool)[:120])
    return {"count": len(tools), "names": names[:_MAX_LOG_LIST_ITEMS]}


def _sanitize_for_log(value: Any) -> Any:
    if isinstance(value, str):
        if len(value) <= _MAX_LOG_TEXT_CHARS:
            return value
        return value[:_MAX_LOG_TEXT_CHARS] + f"...<truncated {len(value) - _MAX_LOG_TEXT_CHARS} chars>"
    if isinstance(value, list):
        items = [_sanitize_for_log(item) for item in value[:_MAX_LOG_LIST_ITEMS]]
        if len(value) > _MAX_LOG_LIST_ITEMS:
            items.append(f"...<truncated {len(value) - _MAX_LOG_LIST_ITEMS} list items>")
        return items
    if isinstance(value, dict):
        return {key: _sanitize_for_log(item) for key, item in value.items()}
    return value


def _extract_usage(response: Any) -> dict[str, Any] | None:
    try:
        if response is None:
            return None
        if hasattr(response, "usage"):
            usage = response.usage
            if hasattr(usage, "model_dump"):
                return usage.model_dump(exclude_none=True)
            if isinstance(usage, dict):
                return usage
        if isinstance(response, dict):
            return response.get("usage")
    except Exception:  # pragma: no cover
        return None
    return None


def _extract_finish_reason(response: Any) -> str | None:
    try:
        choices = getattr(response, "choices", None)
        if choices is None and isinstance(response, dict):
            choices = response.get("choices")
        if not choices:
            return None
        first = choices[0]
        return getattr(first, "finish_reason", None) or (first or {}).get("finish_reason")  # type: ignore[union-attr]
    except Exception:  # pragma: no cover
        return None


def _has_tool_calls(response: Any) -> bool:
    try:
        choices = getattr(response, "choices", None)
        if choices is None and isinstance(response, dict):
            choices = response.get("choices") or []
        if not choices:
            return False
        first = choices[0]
        message = getattr(first, "message", None) or (first or {}).get("message")  # type: ignore[union-attr]
        if message is None:
            return False
        tool_calls = getattr(message, "tool_calls", None)
        if tool_calls is None and isinstance(message, dict):
            tool_calls = message.get("tool_calls")
        return bool(tool_calls)
    except Exception:  # pragma: no cover
        return False

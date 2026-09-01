"""Agent 路由入口。

统一对外: run_agent(role, *args) → 反射定位到 app.agent.sub_agent.<role.value>.run

附带职责：
- 在调用子 agent 期间设置 logger 的当前角色。
- 推断 ObsScope 并注入：让 LLM 调用日志同时落到
  ``<artifacts_dir>/conversations/<agent>/turn-NNNN.json`` 与
  ``<artifacts_dir>/events.jsonl``。
"""

from __future__ import annotations

import importlib
import time
from typing import Any

from app.agent.logger import (
    ObsScope,
    get_obs_scope,
    reset_agent_role,
    reset_obs_scope,
    set_agent_role,
    set_obs_scope,
    write_event,
)
from app.agent.run_scope import resolve_run_scope
from app.agent.types import AgentRole

_SUB_AGENT_PACKAGE = "app.agent.sub_agent"


def run_agent(role: AgentRole, *args):
    """按 role 路由到对应的 sub_agent.run(...)，透传所有位置参数。"""
    module_name = f"{_SUB_AGENT_PACKAGE}.{role.value}"
    module = importlib.import_module(module_name)
    if not hasattr(module, "run"):
        raise AttributeError(f"{module_name} 缺少 run(...) 入口函数")

    role_token = set_agent_role(role.value)
    scope_token = _ensure_obs_scope(role, args)
    started = time.perf_counter()
    write_event(
        "agent_start",
        agent=role.value,
        args=[str(a) for a in args[:3]],
    )
    try:
        result = module.run(*args)
    except BaseException as err:
        write_event(
            "agent_error",
            agent=role.value,
            error_type=type(err).__name__,
            error=str(err),
            sub_exceptions=_flatten_exception_group(err),
            elapsed=time.perf_counter() - started,
        )
        raise
    finally:
        write_event(
            "agent_end",
            agent=role.value,
            elapsed=time.perf_counter() - started,
            result_summary=_summarize_result(result if "result" in dir() else None),
        )
        if scope_token is not None:
            reset_obs_scope(scope_token)
        reset_agent_role(role_token)
    return result


def _ensure_obs_scope(role: AgentRole, args: tuple[Any, ...]) -> object | None:
    """如果当前没有 scope，则按 args 推断一个；否则不动。

    pipeline.py 会逐个调用 run_agent，每次自然推断；如果调用方已经
    自己 set_obs_scope（例如长流程串多个 agent），就不覆盖。
    """
    if get_obs_scope() is not None:
        return None

    project_path: str | None = None
    run_id: str | None = None
    if args:
        first = args[0]
        if isinstance(first, str):
            project_path = first
        if len(args) >= 2 and isinstance(args[1], str):
            run_id = args[1]

    if not project_path:
        return None

    try:
        run_scope = resolve_run_scope(project_path, run_id)
    except Exception:
        return None

    obs = ObsScope(
        project_path=project_path,
        project_root=run_scope.project_root,
        artifacts_dir=run_scope.artifacts_dir,
        mode=run_scope.mode,
        run_id=run_scope.run_id,
        target_rel_dir=run_scope.target_rel_dir,
        agent=role.value,
    )
    return set_obs_scope(obs)


def _summarize_result(result: Any) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None
    keep = ("status", "summary", "elapsed_seconds", "scope")
    return {k: result.get(k) for k in keep if k in result}


def _flatten_exception_group(err: BaseException) -> list[dict[str, Any]]:
    """Recursively flatten ``ExceptionGroup`` so agent_error captures the
    actual sub-exceptions (anyio / TaskGroup hide the real failure otherwise)."""
    out: list[dict[str, Any]] = []

    def _walk(exc: BaseException) -> None:
        children = getattr(exc, "exceptions", None)
        if children:
            for child in children:
                _walk(child)
            return
        out.append(
            {
                "type": type(exc).__name__,
                "msg": str(exc),
            }
        )

    _walk(err)
    return out

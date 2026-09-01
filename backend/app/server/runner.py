"""Run DefectMine scan subprocesses and stream output to the frontend."""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

from app.server.paths import PROJECT_ROOT_DIR


BACKEND_DIR = PROJECT_ROOT_DIR / "backend"

# 后台进程管理（内存级，重启后丢失，足够单机使用）
_RUN_LOCK = threading.Lock()
_RUNS: dict[str, "RunState"] = {}


_RUN_ID_RE = re.compile(r"run_id=([0-9A-Za-z_\-]+)")


@dataclass
class RunState:
    run_id: str
    cmd: list[str]
    cwd: str
    status: str = "pending"  # pending|running|done|error|killed
    return_code: int | None = None
    started_at: float | None = None
    finished_at: float | None = None
    output_lines: list[str] = field(default_factory=list)
    detected_run_id: str | None = None  # specific 命令打印的 run_id
    detected_target_rel_dir: str | None = None
    detected_artifacts_dir: str | None = None
    process: subprocess.Popen | None = None
    listeners: list[asyncio.Queue] = field(default_factory=list)
    loop: asyncio.AbstractEventLoop | None = None


def _python_executable() -> str:
    return sys.executable or "python"


def _build_cmd(kind: str, payload: dict[str, Any]) -> list[str]:
    py = _python_executable()
    if kind == "scan":
        # 内部使用：在子进程里跑指定 scan 的多个 agent
        cmd = [
            py,
            "-m",
            "app.server.scan_runner_cli",
            payload["project_path"],
            payload["scan_id"],
        ]
        agents = payload.get("agents")
        if agents:
            cmd.append(f"--agents={','.join(agents)}")
        if payload.get("resume"):
            cmd.append("--resume")
        return cmd
    raise ValueError(f"未知命令类型：{kind}")


def start_run(kind: str, payload: dict[str, Any]) -> RunState:
    cmd = _build_cmd(kind, payload)
    run_id = uuid.uuid4().hex[:12]

    state = RunState(run_id=run_id, cmd=cmd, cwd=str(BACKEND_DIR))

    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUNBUFFERED", "1")

    try:
        # 主事件循环（FastAPI 在跑），用于 call_soon_threadsafe
        state.loop = asyncio.get_event_loop()
    except RuntimeError:
        state.loop = None

    proc = subprocess.Popen(
        cmd,
        cwd=str(BACKEND_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    state.process = proc
    state.status = "running"
    state.started_at = _now()

    with _RUN_LOCK:
        _RUNS[run_id] = state

    threading.Thread(target=_pump_output, args=(state,), daemon=True).start()
    return state


def get_run(run_id: str) -> RunState | None:
    with _RUN_LOCK:
        return _RUNS.get(run_id)


def list_runs() -> list[dict[str, Any]]:
    with _RUN_LOCK:
        out: list[dict[str, Any]] = []
        for s in _RUNS.values():
            out.append(
                {
                    "run_id": s.run_id,
                    "cmd": s.cmd,
                    "status": s.status,
                    "return_code": s.return_code,
                    "started_at": s.started_at,
                    "finished_at": s.finished_at,
                    "detected_run_id": s.detected_run_id,
                }
            )
        out.sort(key=lambda r: r.get("started_at") or 0, reverse=True)
        return out


def kill_run(run_id: str) -> bool:
    with _RUN_LOCK:
        s = _RUNS.get(run_id)
    if not s or s.process is None:
        return False
    if s.status not in {"running", "pending"}:
        return False
    try:
        s.process.terminate()
    except OSError:
        return False
    s.status = "killed"
    return True


async def stream_run(run_id: str) -> AsyncIterator[str]:
    """SSE 流：先发送已缓存的所有行，再监听新行。"""
    state = get_run(run_id)
    if state is None:
        yield _sse({"type": "error", "message": f"run not found: {run_id}"})
        return

    queue: asyncio.Queue = asyncio.Queue()
    state.listeners.append(queue)

    # 发送已经积累的内容
    for line in list(state.output_lines):
        yield _sse({"type": "stdout", "line": line})

    if state.status not in {"running", "pending"}:
        yield _sse(
            {
                "type": "status",
                "status": state.status,
                "return_code": state.return_code,
                "detected_run_id": state.detected_run_id,
                "detected_target_rel_dir": state.detected_target_rel_dir,
                "detected_artifacts_dir": state.detected_artifacts_dir,
            }
        )
        yield _sse({"type": "end"})
        return

    try:
        while True:
            item = await queue.get()
            if item is None:
                # 哨兵：进程结束
                yield _sse(
                    {
                        "type": "status",
                        "status": state.status,
                        "return_code": state.return_code,
                        "detected_run_id": state.detected_run_id,
                        "detected_target_rel_dir": state.detected_target_rel_dir,
                        "detected_artifacts_dir": state.detected_artifacts_dir,
                    }
                )
                yield _sse({"type": "end"})
                return
            yield _sse(item)
    finally:
        try:
            state.listeners.remove(queue)
        except ValueError:
            pass


def _sse(payload: dict[str, Any]) -> str:
    import json

    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _now() -> float:
    import time

    return time.time()


def _pump_output(state: RunState) -> None:
    proc = state.process
    if proc is None or proc.stdout is None:
        return
    try:
        for raw in proc.stdout:
            line = raw.rstrip("\r\n")
            state.output_lines.append(line)
            _detect(state, line)
            _broadcast(state, {"type": "stdout", "line": line})
        proc.stdout.close()
    except Exception as err:  # pragma: no cover
        _broadcast(state, {"type": "error", "message": str(err)})

    rc = proc.wait()
    state.return_code = rc
    state.finished_at = _now()
    if state.status == "killed":
        pass
    elif rc == 0:
        state.status = "done"
    else:
        state.status = "error"

    _broadcast(state, None)  # 哨兵


def _detect(state: RunState, line: str) -> None:
    # 解析 specific 命令打印的 run_id / target_rel_dir / artifacts_dir
    if state.detected_run_id is None:
        m = _RUN_ID_RE.search(line)
        if m:
            state.detected_run_id = m.group(1)
    if line.startswith("target_rel_dir="):
        state.detected_target_rel_dir = line.split("=", 1)[1].strip()
    if line.startswith("artifacts_dir="):
        state.detected_artifacts_dir = line.split("=", 1)[1].strip()


def _broadcast(state: RunState, item: dict[str, Any] | None) -> None:
    loop = state.loop
    for queue in list(state.listeners):
        if loop is not None:
            loop.call_soon_threadsafe(queue.put_nowait, item)
        else:
            try:
                queue.put_nowait(item)
            except Exception:
                pass

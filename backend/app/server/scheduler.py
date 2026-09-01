"""扫描定时调度器 + 启动孤儿恢复。

设计：
- 单进程内启动一个 daemon 线程，每 ``TICK_SECONDS`` 秒扫描所有 scan.json。
- 找到 ``status="pending" / "stopped"`` 且 ``scheduled_at`` <= now 的，立即启动。
- 不依赖 cron 之类的外部组件；FastAPI 启动 / 关闭事件挂钩生命周期。
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Iterable

from app.server import runner as run_mod
from app.server import scans as scans_mod


TICK_SECONDS = 15


_thread: threading.Thread | None = None
_stop_event: threading.Event = threading.Event()


def start_scheduler() -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop_event.clear()
    n = scans_mod.mark_orphan_running_as_stopped()
    if n > 0:
        print(f"[scheduler] 启动时清理孤儿运行 {n} 个，标记为 stopped")
    _thread = threading.Thread(target=_loop, name="dm-scheduler", daemon=True)
    _thread.start()
    print("[scheduler] 已启动")


def stop_scheduler() -> None:
    _stop_event.set()


def _loop() -> None:
    while not _stop_event.is_set():
        try:
            _tick()
        except Exception as err:  # pragma: no cover - 后台线程不挂
            print(f"[scheduler] tick error: {err}")
        if _stop_event.wait(timeout=TICK_SECONDS):
            return


def _tick() -> None:
    now = datetime.now().astimezone()
    for meta in _due_scans(now):
        scan_id = meta["scan_id"]
        project_path = meta["project_path"]
        # 防止重复触发：触发前先把 scheduled_at 清空
        scans_mod.update_scan_status(
            project_path,
            scan_id,
            scheduled_at=None,
        )
        agents = list(meta.get("agents") or [])
        # 已有部分 completed 时按 resume 跑
        resume = bool(meta.get("completed_agents"))
        try:
            state = run_mod.start_run(
                "scan",
                {
                    "project_path": project_path,
                    "scan_id": scan_id,
                    "agents": agents,
                    "resume": resume,
                },
            )
            scans_mod.update_scan_status(
                project_path,
                scan_id,
                last_run_id=state.run_id,
            )
            print(
                f"[scheduler] 启动到点扫描 {project_path} / {scan_id} "
                f"(resume={resume}, run_id={state.run_id})"
            )
        except Exception as err:
            print(f"[scheduler] 启动失败 {scan_id}: {err}")


def _due_scans(now: datetime) -> Iterable[dict]:
    for meta in scans_mod.list_all_scans():
        if meta.get("legacy"):
            continue
        if meta.get("status") not in ("pending", "stopped"):
            continue
        sched = meta.get("scheduled_at")
        if not sched:
            continue
        try:
            target = datetime.fromisoformat(sched)
        except ValueError:
            continue
        # iso 字符串可能没带时区；尝试归一
        if target.tzinfo is None:
            target = target.astimezone()
        if target <= now:
            yield meta

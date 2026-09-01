"""被前端 / API 触发，在子进程中执行一次完整扫描。

用法::

    python -m app.server.scan_runner_cli <project_path> <scan_id> [--agents=a,b,c] [--resume]

行为：
- ``--agents`` 不传时使用 scan.json 中保存的 agents 列表。
- ``--resume`` 会跳过 scan.json 中 ``completed_agents`` 已经完成的 agent，
  实现"断点恢复"。重跑（不带 --resume）会清空 completed_agents 并从头开始。
- stdout/stderr 实时写到 ``<scan_dir>/console.log`` 末尾，方便页面切换或重新打开后回看。
"""

from __future__ import annotations

import io
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path

from app.agent import run_agent
from app.agent.logger import (
    ObsScope,
    reset_obs_scope,
    set_obs_scope,
    write_event,
)
from app.agent.run_scope import resolve_run_scope
from app.agent.types import AgentRole
from app.server import scans as scans_mod


CONSOLE_FILENAME = "console.log"
AUDIT_PROGRESS_FILENAME = "audit_progress.jsonl"
CALLSCAN_PROGRESS_FILENAME = "callscan_progress.jsonl"


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class TeeWriter(io.TextIOBase):
    """同时写到原始流（被 SSE 抓取）与磁盘 console.log。"""

    def __init__(self, primary, log_path: Path) -> None:
        self.primary = primary
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # 用 buffered + flush 保证子进程中断后日志不丢
        self.fp = self.log_path.open("a", encoding="utf-8", buffering=1)

    def write(self, s: str) -> int:  # type: ignore[override]
        try:
            self.primary.write(s)
            self.primary.flush()
        except Exception:  # pragma: no cover
            pass
        try:
            self.fp.write(s)
            self.fp.flush()
        except Exception:  # pragma: no cover
            pass
        return len(s)

    def flush(self) -> None:  # type: ignore[override]
        try:
            self.primary.flush()
        except Exception:
            pass
        try:
            self.fp.flush()
        except Exception:
            pass

    def close(self) -> None:  # type: ignore[override]
        try:
            self.fp.flush()
            self.fp.close()
        except Exception:
            pass


def _parse_args(argv: list[str]) -> tuple[str, str, list[str] | None, bool]:
    if len(argv) < 2:
        print(
            "usage: scan_runner_cli <project_path> <scan_id> [--agents=a,b] [--resume]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    project_path, scan_id = argv[0], argv[1]
    agents: list[str] | None = None
    resume = False
    for raw in argv[2:]:
        if raw.startswith("--agents="):
            agents = [a.strip() for a in raw.split("=", 1)[1].split(",") if a.strip()]
        elif raw == "--resume":
            resume = True
        elif raw.startswith("-"):
            print(f"未知参数：{raw}", file=sys.stderr)
            raise SystemExit(2)
    return project_path, scan_id, agents, resume


def _run_pipeline(
    project_path: str,
    scan_id: str,
    agents: list[str],
    resume: bool,
) -> int:
    unsupported = [a for a in agents if a not in scans_mod.ALL_AGENTS]
    if unsupported:
        print(
            "error: unsupported scan workflow agent(s): "
            + ", ".join(unsupported)
            + f"; allowed: {','.join(scans_mod.ALL_AGENTS)}",
            file=sys.stderr,
        )
        return 2

    meta = scans_mod.get_scan(project_path, scan_id)
    target_mode = (meta.get("target") or {}).get("mode", "all")
    target_rel_dir = (meta.get("target") or {}).get("rel_dir")
    completed: list[str] = list(meta.get("completed_agents") or [])

    # 非 resume 时清掉 completed_agents 与 agent 级链/sink 断点
    if not resume:
        completed = []
        scans_mod.update_scan_status(
            project_path, scan_id, completed_agents=[], last_error=None,
        )
        scan_dir = scans_mod._scan_dir(project_path, scan_id)
        for name in (AUDIT_PROGRESS_FILENAME, CALLSCAN_PROGRESS_FILENAME):
            progress_path = scan_dir / name
            if progress_path.is_file():
                progress_path.unlink()

    pending = [a for a in agents if a not in completed]
    skipped = [a for a in agents if a in completed]

    print(f"=== 扫描启动 scan_id={scan_id} ===")
    print(f"project={project_path}")
    print(f"target_mode={target_mode}", end="")
    if target_rel_dir:
        print(f", target_rel_dir={target_rel_dir}")
    else:
        print()
    print(f"agents={','.join(agents)}")
    if skipped:
        print(f"resume：跳过已完成 {','.join(skipped)}")
    print(f"待执行：{','.join(pending) or '（无）'}")
    print()

    if not pending:
        # 所有 agent 都已完成
        scans_mod.update_scan_status(
            project_path,
            scan_id,
            status="done",
            current_agent=None,
            finished_at=_now_iso(),
        )
        print("=== 全部 agent 已在历史中完成，无需执行 ===")
        return 0

    run_scope = resolve_run_scope(project_path, scan_id)
    obs = ObsScope(
        project_path=project_path,
        project_root=run_scope.project_root,
        artifacts_dir=run_scope.artifacts_dir,
        mode=run_scope.mode,
        run_id=scan_id,
        target_rel_dir=run_scope.target_rel_dir,
    )
    obs_token = set_obs_scope(obs)

    started = time.perf_counter()
    started_iso = _now_iso()
    scans_mod.update_scan_status(
        project_path,
        scan_id,
        status="running",
        started_at=started_iso,
        finished_at=None,
        duration_seconds=None,
    )
    write_event(
        "scan_start",
        scan_id=scan_id,
        agents=agents,
        resumed=resume,
        skipped=skipped,
        target_mode=target_mode,
        target_rel_dir=target_rel_dir,
    )

    try:
        for agent_name in pending:
            try:
                role = AgentRole(agent_name)
            except ValueError:
                print(f"[warn] 跳过未知 agent: {agent_name}", file=sys.stderr)
                continue

            scans_mod.update_scan_status(
                project_path, scan_id, current_agent=agent_name
            )
            write_event("scan_step_start", agent=agent_name)
            print(f"--- 运行 {agent_name} ---")
            t0 = time.perf_counter()
            try:
                run_agent(role, project_path, scan_id)
            except BaseException as err:  # noqa: BLE001
                write_event(
                    "scan_step_error",
                    agent=agent_name,
                    error_type=type(err).__name__,
                    error=str(err),
                )
                if isinstance(err, KeyboardInterrupt):
                    print(f"[info] {agent_name} 已被中断（KeyboardInterrupt）", file=sys.stderr)
                else:
                    print(
                        f"[error] {agent_name} 失败：{type(err).__name__}: {err}",
                        file=sys.stderr,
                    )
                raise
            elapsed = time.perf_counter() - t0
            scans_mod.append_completed_agent(project_path, scan_id, agent_name)
            write_event("scan_step_end", agent=agent_name, elapsed=elapsed)
            print(f"  ↳ done in {elapsed:.2f}s")

    except BaseException as err:
        # 区分用户主动停止（SIGTERM/KeyboardInterrupt）与真实错误
        is_stop = isinstance(err, (KeyboardInterrupt, SystemExit))
        scans_mod.update_scan_status(
            project_path,
            scan_id,
            status="stopped" if is_stop else "error",
            current_agent=None,
            finished_at=_now_iso(),
            duration_seconds=time.perf_counter() - started,
            last_error=None if is_stop else f"{type(err).__name__}: {err}",
        )
        write_event(
            "scan_end",
            scan_id=scan_id,
            status="stopped" if is_stop else "error",
            elapsed=time.perf_counter() - started,
        )
        reset_obs_scope(obs_token)
        return 1 if not is_stop else 130

    elapsed = time.perf_counter() - started
    scans_mod.update_scan_status(
        project_path,
        scan_id,
        status="done",
        current_agent=None,
        finished_at=_now_iso(),
        duration_seconds=elapsed,
        last_error=None,
    )
    write_event(
        "scan_end",
        scan_id=scan_id,
        status="done",
        elapsed=elapsed,
    )
    reset_obs_scope(obs_token)
    print(f"\n=== 扫描完成 总耗时 {elapsed:.2f}s ===")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    project_path, scan_id, cli_agents, resume = _parse_args(args)

    meta = scans_mod.get_scan(project_path, scan_id)
    agents = cli_agents or list(meta.get("agents") or [])
    if not agents:
        print("error: no agents specified", file=sys.stderr)
        return 2

    # 持久化控制台输出到 <scan_dir>/console.log（同时仍写到 stdout）
    scan_dir = scans_mod._scan_dir(project_path, scan_id)
    log_path = scan_dir / CONSOLE_FILENAME
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # 写一行启动分隔
    with log_path.open("a", encoding="utf-8") as fp:
        fp.write(f"\n========== {_now_iso()} 启动（resume={resume}） ==========\n")

    tee_out = TeeWriter(sys.__stdout__, log_path)
    tee_err = TeeWriter(sys.__stderr__, log_path)
    try:
        with redirect_stdout(tee_out), redirect_stderr(tee_err):
            return _run_pipeline(project_path, scan_id, agents, resume)
    finally:
        tee_out.close()
        tee_err.close()


if __name__ == "__main__":
    sys.exit(main())

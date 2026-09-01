"""扫描（Scan）模型与 CRUD。

每次扫描都是独立的存档，目录结构：

    .defectmine/scans/<scan_id>/
        scan.json            # 元信息：名称、目标、Agent 选择、状态、Ground truth
        verification.json    # 用户对 finding 的人工标注（误报 / 漏报 / 真阳）
        events.jsonl         # 由 logger.write_event 追加
        conversations/       # 由 logger 落盘的 LLM 对话
        treescan_agent.json  # treescan 产物
        callscan_*.{json,jsonl,md}
        audit_*.{json,md}

兼容旧数据：
- ``.defectmine/<artifact>``：root run 视为 ``scan_id="legacy-root"``，只读。
- ``.defectmine/specific/<run_id>/``：每个目录视为
  ``scan_id="legacy-<run_id>"`` 的旧扫描，只读。
"""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from app.server import json_io
from app.server.paths import (
    ARTIFACTS_DIRNAME,
    SPECIFIC_DIRNAME,
    project_dir,
)


SCANS_DIRNAME = "scans"
SCAN_META_FILENAME = "scan.json"
VERIFICATION_FILENAME = "verification.json"
AUDIT_FAILURES_JSONL = "audit_failures.jsonl"
AUDIT_AGENT_JSON = "audit_agent.json"
LEGACY_ROOT_ID = "legacy-root"
LEGACY_PREFIX = "legacy-"
REVIEW_TRACKS = {
    "codex": {
        "verdict": "Codex核验",
        "review": "Codex-Review",
        "marked_at": "Codex核验时间",
    },
    "manual": {
        "verdict": "人工核验",
        "review": "人工-Review",
        "marked_at": "人工核验时间",
    },
    "cc": {
        "verdict": "CC核验",
        "review": "CC-Review",
        "marked_at": "CC核验时间",
    },
}
REVIEW_VERDICTS = ("true_positive", "false_positive", "uncertain", "clear")

# 默认可选的 agents
ALL_AGENTS = ["treescan", "callscan", "dataflowscan", "auditor"]

DEFAULT_SCAN_OPTIONS: dict[str, Any] = {
    "callscan_use_llm": True,
    "callscan_concurrency": 3,
    "auditor_concurrency": 8,
}

MAX_AUDITOR_CONCURRENCY = 2500


def _normalize_options(raw: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(DEFAULT_SCAN_OPTIONS)
    if not isinstance(raw, dict):
        return out
    if "callscan_use_llm" in raw:
        out["callscan_use_llm"] = bool(raw["callscan_use_llm"])
    if "callscan_concurrency" in raw:
        try:
            out["callscan_concurrency"] = max(1, min(16, int(raw["callscan_concurrency"])))
        except (TypeError, ValueError):
            pass
    if "auditor_concurrency" in raw:
        try:
            out["auditor_concurrency"] = max(
                1, min(MAX_AUDITOR_CONCURRENCY, int(raw["auditor_concurrency"]))
            )
        except (TypeError, ValueError):
            pass
    return out


# ---------- 路径工具 ----------


def _scans_root(project_path: str) -> Path:
    return project_dir(project_path) / ARTIFACTS_DIRNAME / SCANS_DIRNAME


def _scan_dir(project_path: str, scan_id: str) -> Path:
    if scan_id.startswith(LEGACY_PREFIX):
        if scan_id == LEGACY_ROOT_ID:
            return project_dir(project_path) / ARTIFACTS_DIRNAME
        # legacy-<run_id>
        run_id = scan_id[len(LEGACY_PREFIX):]
        return project_dir(project_path) / ARTIFACTS_DIRNAME / SPECIFIC_DIRNAME / run_id

    base = _scans_root(project_path)
    candidate = (base / scan_id).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as err:
        raise ValueError(f"非法 scan_id: {scan_id}") from err
    return candidate


def is_legacy(scan_id: str) -> bool:
    return scan_id.startswith(LEGACY_PREFIX)


# ---------- 元信息读写 ----------


def _new_scan_id() -> str:
    while True:
        sid = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
        if "-" not in sid:
            continue
        return sid


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _read_json(path: Path) -> dict[str, Any] | None:
    return json_io.read_json_object(path)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    json_io.write_json(path, data, indent=True)


# ---------- 创建 / 读取 / 更新 ----------


def create_scan(
    project_path: str,
    *,
    name: str,
    target_mode: str = "all",
    target_rel_dir: str | None = None,
    agents: Iterable[str] = ALL_AGENTS,
    callscan_use_llm: bool | None = None,
) -> dict[str, Any]:
    proj_root = project_dir(project_path)

    if target_mode not in ("all", "directory"):
        raise ValueError("target_mode 必须为 all / directory")

    rel_dir: str | None = None
    if target_mode == "directory":
        rel_dir = (target_rel_dir or "").strip().replace("\\", "/").strip("/")
        if not rel_dir:
            raise ValueError("directory 模式必须提供 target_rel_dir")
        if rel_dir == "." or rel_dir.startswith("../") or "/.." in rel_dir:
            raise ValueError("target_rel_dir 不能越界")
        candidate = (proj_root / rel_dir).resolve()
        try:
            candidate.relative_to(proj_root.resolve())
        except ValueError as err:
            raise ValueError("target_rel_dir 必须位于项目内") from err
        if not candidate.is_dir():
            raise FileNotFoundError(f"目标目录不存在: {candidate}")

    selected = [a for a in agents if a in ALL_AGENTS]
    if not selected:
        raise ValueError("至少选择一个 Agent")

    scans_root = _scans_root(project_path)
    scans_root.mkdir(parents=True, exist_ok=True)

    scan_id = _new_scan_id()
    scan_dir = scans_root / scan_id
    scan_dir.mkdir(parents=True, exist_ok=False)

    meta = {
        "scan_id": scan_id,
        "name": name.strip() or _default_name(target_mode, rel_dir),
        "project_path": project_path,
        "project_root": str(proj_root),
        "target": {"mode": target_mode, "rel_dir": rel_dir},
        "agents": selected,
        "status": "pending",
        "current_agent": None,
        "completed_agents": [],
        "scheduled_at": None,
        "console_log": "console.log",
        "created_at": _now_iso(),
        "started_at": None,
        "finished_at": None,
        "duration_seconds": None,
        "last_run_id": None,
        "ground_truth": {
            "expected_total": None,
            "missed": None,
            "notes": "",
        },
        "options": _normalize_options(
            {"callscan_use_llm": callscan_use_llm}
            if callscan_use_llm is not None
            else None
        ),
    }
    _write_json(scan_dir / SCAN_META_FILENAME, meta)
    return meta


def _default_name(target_mode: str, rel_dir: str | None) -> str:
    if target_mode == "all":
        return "全仓库扫描"
    return f"目录扫描 · {rel_dir}" if rel_dir else "目录扫描"


def get_scan(project_path: str, scan_id: str) -> dict[str, Any]:
    if scan_id.startswith(LEGACY_PREFIX):
        return _virtual_legacy_meta(project_path, scan_id)
    path = _scan_dir(project_path, scan_id) / SCAN_META_FILENAME
    meta = _read_json(path)
    if not meta:
        raise FileNotFoundError(f"扫描不存在: {scan_id}")
    meta["options"] = _normalize_options(meta.get("options"))
    return meta


def update_scan(project_path: str, scan_id: str, fields: dict[str, Any]) -> dict[str, Any]:
    if is_legacy(scan_id):
        raise ValueError("旧扫描记录不可编辑")
    path = _scan_dir(project_path, scan_id) / SCAN_META_FILENAME
    meta = _read_json(path)
    if not meta:
        raise FileNotFoundError(f"扫描不存在: {scan_id}")

    # 仅允许修改一部分字段
    allowed_top = {"name", "agents", "target", "ground_truth", "options"}
    for k, v in fields.items():
        if k not in allowed_top:
            continue
        if k == "options":
            merged = _normalize_options(meta.get("options"))
            if isinstance(v, dict):
                if "callscan_use_llm" in v:
                    merged["callscan_use_llm"] = bool(v["callscan_use_llm"])
                if "callscan_concurrency" in v:
                    try:
                        merged["callscan_concurrency"] = max(
                            1, min(16, int(v["callscan_concurrency"]))
                        )
                    except (TypeError, ValueError):
                        pass
                if "auditor_concurrency" in v:
                    try:
                        merged["auditor_concurrency"] = max(
                            1,
                            min(MAX_AUDITOR_CONCURRENCY, int(v["auditor_concurrency"])),
                        )
                    except (TypeError, ValueError):
                        pass
            meta["options"] = merged
        elif k == "agents":
            meta[k] = [a for a in (v or []) if a in ALL_AGENTS] or meta.get(k)
        elif k == "target":
            mode = (v or {}).get("mode") or meta["target"]["mode"]
            rel = (v or {}).get("rel_dir")
            if mode not in ("all", "directory"):
                raise ValueError("target_mode 非法")
            if mode == "directory":
                rel = (rel or "").strip().replace("\\", "/").strip("/") or None
                if not rel:
                    raise ValueError("directory 模式必须提供 rel_dir")
            else:
                rel = None
            meta["target"] = {"mode": mode, "rel_dir": rel}
        elif k == "ground_truth":
            meta["ground_truth"] = _normalize_ground_truth(v or {})
        else:
            meta[k] = v
    meta["options"] = _normalize_options(meta.get("options"))
    _write_json(path, meta)
    return meta


def _normalize_ground_truth(gt: dict[str, Any]) -> dict[str, Any]:
    def _opt_int(v: Any) -> int | None:
        if v is None or v == "":
            return None
        try:
            n = int(v)
            return n if n >= 0 else None
        except (TypeError, ValueError):
            return None

    return {
        "expected_total": _opt_int(gt.get("expected_total")),
        "missed": _opt_int(gt.get("missed")),
        "notes": str(gt.get("notes") or ""),
    }


def delete_scan(project_path: str, scan_id: str) -> dict[str, Any]:
    if is_legacy(scan_id):
        raise ValueError("旧扫描记录不可删除（请直接清理对应目录）")
    target = _scan_dir(project_path, scan_id)
    meta = _read_json(target / SCAN_META_FILENAME)
    if not target.is_dir() or not meta:
        raise FileNotFoundError(f"扫描不存在: {scan_id}")
    shutil.rmtree(target)
    return meta


def update_scan_status(
    project_path: str,
    scan_id: str,
    *,
    status: str | None = None,
    current_agent: str | None = ...,
    started_at: str | None = ...,
    finished_at: str | None = ...,
    duration_seconds: float | None = ...,
    last_run_id: str | None = ...,
    completed_agents: list[str] | None = ...,
    scheduled_at: str | None = ...,
    last_error: str | None = ...,
) -> dict[str, Any] | None:
    if is_legacy(scan_id):
        return None
    path = _scan_dir(project_path, scan_id) / SCAN_META_FILENAME
    meta = _read_json(path)
    if not meta:
        return None
    if status is not None:
        meta["status"] = status
    if current_agent is not ...:
        meta["current_agent"] = current_agent
    if started_at is not ...:
        meta["started_at"] = started_at
    if finished_at is not ...:
        meta["finished_at"] = finished_at
    if duration_seconds is not ...:
        meta["duration_seconds"] = duration_seconds
    if last_run_id is not ...:
        meta["last_run_id"] = last_run_id
    if completed_agents is not ...:
        meta["completed_agents"] = list(completed_agents) if completed_agents else []
    if scheduled_at is not ...:
        meta["scheduled_at"] = scheduled_at
    if last_error is not ...:
        meta["last_error"] = last_error
    _write_json(path, meta)
    return meta


def count_audit_failures(project_path: str, scan_id: str) -> int:
    """统计 audit_failures.jsonl 中的失败链数量。"""
    path = _scan_dir(project_path, scan_id) / AUDIT_FAILURES_JSONL
    if not path.is_file():
        return 0
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            if line.strip():
                n += 1
    return n


def prepare_retry_audit_failures(project_path: str, scan_id: str) -> dict[str, Any]:
    """为「重试审计异常项」做准备：去掉 auditor 的完成标记，清空失败日志。

    成功链仍保留在 audit_progress.jsonl；Auditor 以 resume 模式只补跑未完成的链。
    """
    if is_legacy(scan_id):
        raise ValueError("旧扫描记录不可重试")
    base = _scan_dir(project_path, scan_id)
    failure_count = count_audit_failures(project_path, scan_id)
    if failure_count <= 0:
        audit = _read_json(base / AUDIT_AGENT_JSON)
        llm_failed = int((audit or {}).get("summary", {}).get("llm_failed", 0) or 0)
        if llm_failed <= 0:
            raise ValueError("没有可重试的审计异常项（audit_failures.jsonl 为空）")
        failure_count = llm_failed

    meta = _read_json(base / SCAN_META_FILENAME)
    if not meta:
        raise FileNotFoundError(f"扫描不存在: {scan_id}")
    if meta.get("status") == "running":
        raise ValueError("扫描正在运行中，请先停止后再重试异常项")

    callscan = base / "callscan_chains.jsonl"
    legacy_priority = base / "callscan_chains.priority.jsonl"
    dataflow = base / "cross_request_chains.jsonl"
    if not callscan.is_file() and not legacy_priority.is_file() and not dataflow.is_file():
        raise ValueError("missing CallScan candidate chain file; run CallScan first")

    completed = [a for a in list(meta.get("completed_agents") or []) if a != "auditor"]
    failures_path = base / AUDIT_FAILURES_JSONL
    if failures_path.is_file():
        failures_path.write_text("", encoding="utf-8")

    update_scan_status(
        project_path,
        scan_id,
        completed_agents=completed,
        status="pending",
        current_agent=None,
        last_error=None,
    )
    return {"failure_count": failure_count, "agents": ["auditor"]}


def append_completed_agent(project_path: str, scan_id: str, agent: str) -> None:
    if is_legacy(scan_id):
        return
    path = _scan_dir(project_path, scan_id) / SCAN_META_FILENAME
    meta = _read_json(path)
    if not meta:
        return
    completed: list[str] = list(meta.get("completed_agents") or [])
    if agent not in completed:
        completed.append(agent)
    meta["completed_agents"] = completed
    _write_json(path, meta)


def list_all_scans() -> list[dict[str, Any]]:
    """跨项目扫一遍 repo/，返回所有非 legacy 的扫描元信息。

    供任务队列、孤儿恢复使用。
    """
    from app.server.paths import REPO_ROOT, ARTIFACTS_DIRNAME

    if not REPO_ROOT.is_dir():
        return []

    out: list[dict[str, Any]] = []
    for source in sorted(p for p in REPO_ROOT.iterdir() if p.is_dir()):
        if source.name.startswith("."):
            continue
        for owner in sorted(p for p in source.iterdir() if p.is_dir()):
            if owner.name.startswith("."):
                continue
            for repo in sorted(p for p in owner.iterdir() if p.is_dir()):
                if repo.name.startswith("."):
                    continue
                for version in sorted(p for p in repo.iterdir() if p.is_dir()):
                    if version.name.startswith("."):
                        continue
                    project_path = f"{source.name}/{owner.name}/{repo.name}/{version.name}"
                    scans_root = version / ARTIFACTS_DIRNAME / SCANS_DIRNAME
                    if not scans_root.is_dir():
                        continue
                    for d in sorted(p for p in scans_root.iterdir() if p.is_dir()):
                        meta = _read_json(d / SCAN_META_FILENAME)
                        if meta:
                            out.append(_attach_summary(meta, d))
    out.sort(key=lambda m: -(_ts_score(m.get("created_at"))))
    return out


def mark_orphan_running_as_stopped() -> int:
    """启动时调用：把上次崩在 running 的扫描标记为 stopped。

    依据：服务进程刚启动，不会有正在跑的扫描；status=running 一定是孤儿。
    """
    n = 0
    for meta in list_all_scans():
        if meta.get("status") == "running":
            update_scan_status(
                meta["project_path"],
                meta["scan_id"],
                status="stopped",
                current_agent=None,
                finished_at=_now_iso(),
            )
            n += 1
    return n


# ---------- 列出 ----------


def list_scans(project_path: str) -> list[dict[str, Any]]:
    """列出所有扫描，包括旧的 root 与 specific 目录。"""
    out: list[dict[str, Any]] = []

    base = project_dir(project_path) / ARTIFACTS_DIRNAME

    # 1) 新扫描
    new_root = base / SCANS_DIRNAME
    if new_root.is_dir():
        for d in sorted(p for p in new_root.iterdir() if p.is_dir()):
            meta = _read_json(d / SCAN_META_FILENAME)
            if meta:
                out.append(_attach_summary(meta, d))

    # 2) 旧 root（如果存在产物文件）
    if _has_legacy_root_artifacts(base):
        out.append(_virtual_legacy_meta(project_path, LEGACY_ROOT_ID))

    # 3) 旧 specific
    legacy_specific = base / SPECIFIC_DIRNAME
    if legacy_specific.is_dir():
        for d in sorted(p for p in legacy_specific.iterdir() if p.is_dir()):
            scan_id = f"{LEGACY_PREFIX}{d.name}"
            out.append(_virtual_legacy_meta(project_path, scan_id))

    # 排序：新扫描按 created_at 倒序，legacy 在最后
    def sort_key(m: dict[str, Any]) -> tuple[int, str]:
        is_legacy_m = 1 if m.get("legacy") else 0
        return (is_legacy_m, "" if is_legacy_m else (m.get("created_at") or ""))

    out.sort(
        key=lambda m: (m.get("legacy") is True, -(_ts_score(m.get("created_at"))))
    )
    return out


def _ts_score(ts: str | None) -> int:
    if not ts:
        return 0
    try:
        return int(datetime.fromisoformat(ts).timestamp())
    except ValueError:
        return 0


def _has_legacy_root_artifacts(base: Path) -> bool:
    if not base.is_dir():
        return False
    candidates = (
        "treescan_agent.json",
        "callscan_agent.json",
        "dataflow_graph.json",
        "cross_request_chains.jsonl",
        "audit_agent.json",
    )
    return any((base / c).is_file() for c in candidates)


def _virtual_legacy_meta(project_path: str, scan_id: str) -> dict[str, Any]:
    base = _scan_dir(project_path, scan_id)
    if scan_id == LEGACY_ROOT_ID:
        target_rel_dir = None
        target_mode = "all"
        name = "[历史] 全仓库扫描"
        created_at = _stat_iso(base)
    else:
        run_meta = _read_json(base / "run_meta.json") or {}
        target_rel_dir = run_meta.get("target_rel_dir")
        target_mode = "directory" if target_rel_dir else "all"
        rid = scan_id[len(LEGACY_PREFIX):]
        name = run_meta.get("name") or (
            f"[历史] 目录扫描 · {target_rel_dir}" if target_rel_dir else f"[历史] {rid}"
        )
        created_at = run_meta.get("created_at") or _stat_iso(base)

    meta = {
        "scan_id": scan_id,
        "name": name,
        "project_path": project_path,
        "project_root": str(project_dir(project_path)),
        "target": {"mode": target_mode, "rel_dir": target_rel_dir},
        "agents": ALL_AGENTS,
        "status": "done" if _has_artifacts(base) else "pending",
        "current_agent": None,
        "created_at": created_at,
        "started_at": None,
        "finished_at": None,
        "duration_seconds": None,
        "last_run_id": None,
        "ground_truth": {"expected_total": None, "missed": None, "notes": ""},
        "legacy": True,
    }
    return _attach_summary(meta, base)


def _stat_iso(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat(
            timespec="seconds"
        )
    except OSError:
        return None


def _has_artifacts(base: Path) -> bool:
    return any(
        (base / n).is_file()
        for n in ("treescan_agent.json", "callscan_agent.json", "dataflow_graph.json", "audit_agent.json")
    )


def _attach_summary(meta: dict[str, Any], base: Path) -> dict[str, Any]:
    """快速摘要：哪些产物存在 + audit 概要。"""
    artifacts: dict[str, dict[str, Any]] = {}
    for name in (
        "tree.json",
        "treescan_agent.json",
        "callscan_agent.json",
        "callscan_chains.jsonl",
        "callscan_chains.priority.jsonl",
        "callscan_chains.md",
        "dataflow_graph.json",
        "cross_request_chains.jsonl",
        "audit_agent.json",
        "audit_findings.md",
    ):
        p = base / name
        if p.is_file():
            artifacts[name] = {"size": p.stat().st_size, "mtime": p.stat().st_mtime}

    audit = json_io.read_json_cached(base / "audit_agent.json")
    audit_summary = (audit or {}).get("summary") if isinstance(audit, dict) else None
    callscan = json_io.read_json_cached(base / "callscan_agent.json")
    callscan_summary = (callscan or {}).get("summary") if isinstance(callscan, dict) else None
    dataflow = json_io.read_json_cached(base / "dataflow_graph.json")
    dataflow_summary = (dataflow or {}).get("summary") if isinstance(dataflow, dict) else None
    failures_path = base / AUDIT_FAILURES_JSONL
    audit_failure_count = 0
    if failures_path.is_file():
        with failures_path.open(encoding="utf-8", errors="replace") as fp:
            audit_failure_count = sum(1 for line in fp if line.strip())

    out = dict(meta)
    out["options"] = _normalize_options(meta.get("options"))
    out["artifacts"] = artifacts
    out["audit_summary"] = audit_summary
    out["callscan_summary"] = callscan_summary
    out["dataflow_summary"] = dataflow_summary
    out["audit_failure_count"] = audit_failure_count
    return out


# ---------- 标注（误报 / 漏报） ----------


def list_marks(project_path: str, scan_id: str) -> dict[str, Any]:
    base = _scan_dir(project_path, scan_id)
    return _normalize_marks(_read_json(base / VERIFICATION_FILENAME) or {})


def upsert_mark(
    project_path: str,
    scan_id: str,
    chain_id: str,
    *,
    reviewer: str = "manual",
    verdict: str | None = None,
    review: str | None = None,
    user_verdict: str | None = None,
    note: str | None = None,
    favorite: bool | None = None,
) -> dict[str, Any]:
    """更新某条 finding 的三方核验标注。

    reviewer 可选 ``codex | manual | cc``；verdict 可选
    ``true_positive | false_positive | uncertain | clear``。
    兼容旧前端传入的 user_verdict/note，但新值默认写入人工字段。
    """
    reviewer = reviewer or "manual"
    if reviewer not in REVIEW_TRACKS:
        raise ValueError("reviewer 非法")
    if verdict is None and user_verdict is not None:
        verdict = user_verdict
    if review is None and note is not None:
        review = note
    if verdict is not None and verdict not in REVIEW_VERDICTS:
        raise ValueError("verdict 非法")

    base = _scan_dir(project_path, scan_id)
    base.mkdir(parents=True, exist_ok=True)
    path = base / VERIFICATION_FILENAME
    marks = _normalize_marks(_read_json(path) or {})

    current = _normalize_mark(marks.get(chain_id) or {})
    fields = REVIEW_TRACKS[reviewer]

    if verdict == "clear":
        current[fields["verdict"]] = ""
    elif verdict is not None:
        current[fields["verdict"]] = verdict

    if review is not None:
        current[fields["review"]] = review

    if verdict is not None or review is not None:
        current[fields["marked_at"]] = _now_iso()

    if favorite is not None:
        current["favorite"] = bool(favorite)

    if _mark_is_empty(current):
        marks.pop(chain_id, None)
    else:
        marks[chain_id] = current
    _write_json(path, marks)
    return marks


def _empty_mark() -> dict[str, Any]:
    out: dict[str, Any] = {"favorite": False}
    for fields in REVIEW_TRACKS.values():
        out[fields["verdict"]] = ""
        out[fields["review"]] = ""
        out[fields["marked_at"]] = ""
    return out


def _normalize_mark(mark: dict[str, Any]) -> dict[str, Any]:
    out = _empty_mark()
    for fields in REVIEW_TRACKS.values():
        for key in fields.values():
            value = mark.get(key)
            if value is not None:
                out[key] = str(value)

    # 旧格式 ({user_verdict, note, marked_at}) 当作"人工核验"迁入
    manual = REVIEW_TRACKS["manual"]
    if not out[manual["verdict"]] and mark.get("user_verdict"):
        out[manual["verdict"]] = str(mark.get("user_verdict") or "")
    if not out[manual["review"]] and mark.get("note"):
        out[manual["review"]] = str(mark.get("note") or "")
    if not out[manual["marked_at"]] and mark.get("marked_at"):
        out[manual["marked_at"]] = str(mark.get("marked_at") or "")
    out["favorite"] = bool(mark.get("favorite"))
    return out


def _normalize_marks(marks: dict[str, Any]) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for chain_id, mark in marks.items():
        if isinstance(mark, dict):
            item = _normalize_mark(mark)
            if not _mark_is_empty(item):
                normalized[str(chain_id)] = item
    return normalized


def _mark_is_empty(mark: dict[str, Any]) -> bool:
    if mark.get("favorite"):
        return False
    for fields in REVIEW_TRACKS.values():
        if mark.get(fields["verdict"]) or mark.get(fields["review"]):
            return False
    return True

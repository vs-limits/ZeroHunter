from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = WORKSPACE_ROOT / "backend"
REPO_CODE_DIR = WORKSPACE_ROOT / "repo_code"
ARTIFACTS_DIRNAME = ".defectmine"
SCANS_DIRNAME = "scans"
SCAN_INDEX_FILENAME = "index.json"
SCAN_META_FILENAME = "scan.json"
CONSOLE_FILENAME = "console.log"

CORE_ARTIFACTS = {
    "tree.json",
    "treescan_agent.json",
    "treescan_agent.raw.txt",
    "workflow_state.json",
    "scanner_targets.json",
    "scanner_agent.raw.json",
    "scanner_agent.json",
    "callscan_agent.json",
    "callscan_chains.priority.jsonl",
    "audit_agent.json",
    "audit_findings.md",
}

RunStatus = Literal["pending", "running", "done", "error", "killed"]


app = FastAPI(title="DefectMine Workbench API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CreateScanRequest(BaseModel):
    project_path: str = Field(..., min_length=1)
    name: str | None = None
    step: str = "all"
    audit_limit: int | None = None
    priority_chain_limit: int | None = None
    audit_dry_run: bool = False


class UpdateScanRequest(BaseModel):
    name: str | None = None
    step: str | None = None
    audit_limit: int | None = None
    priority_chain_limit: int | None = None
    audit_dry_run: bool | None = None


class StartScanRequest(BaseModel):
    project_path: str = Field(..., min_length=1)
    step: str | None = None
    audit_limit: int | None = None
    priority_chain_limit: int | None = None
    audit_dry_run: bool | None = None


class ImportProjectRequest(BaseModel):
    project_path: str = Field(..., min_length=1)


@dataclass
class RunProcess:
    run_id: str
    scan_id: str
    project_path: str
    process: subprocess.Popen[str]
    log_path: Path
    cmd: list[str]
    priority_chain_limit: int | None = None
    audit_limit: int | None = None
    audit_dry_run: bool = False
    status: RunStatus = "running"
    return_code: int | None = None
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    last_message: str = "扫描进程已启动"
    error_message: str = ""


RUNS: dict[str, RunProcess] = {}


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "workspace_root": str(WORKSPACE_ROOT)}


@app.get("/api/projects")
def list_projects() -> dict[str, Any]:
    projects = [_project_summary(path) for path in _iter_project_roots()]
    projects.sort(key=lambda item: item["project_path"])
    return {"items": projects}


@app.get("/api/projects/{project_path:path}")
def get_project(project_path: str) -> dict[str, Any]:
    root = _resolve_project_root(project_path)
    return _project_summary(root)


@app.post("/api/projects/import")
def import_project(req: ImportProjectRequest) -> dict[str, Any]:
    root = _resolve_project_root(req.project_path)
    # 工作台导入只负责把 repo_code 下的项目纳入资产列表；首次扫描前可能还没有 .defectmine。
    # 这里创建一个轻量占位目录，让该项目能被 /api/projects 稳定发现和继续新建扫描。
    _artifacts_dir(root).mkdir(parents=True, exist_ok=True)
    return _project_summary(root)


@app.get("/api/dashboard")
def dashboard() -> dict[str, Any]:
    projects = [_project_summary(path) for path in _iter_project_roots()]
    audit = _merge_audit_summaries([item.get("audit_summary", {}) for item in projects])
    return {
        "projects": len(projects),
        "scans": sum(item.get("scan_count", 0) for item in projects),
        "artifacts_ready": sum(1 for item in projects if item.get("has_artifacts")),
        "audit_summary": audit,
        "items": projects,
    }


@app.get("/api/scans")
def list_scans(project_path: str = Query(...)) -> dict[str, Any]:
    root = _resolve_project_root(project_path)
    scans = _read_scan_index(root)
    return {"items": [_hydrate_scan(root, scan) for scan in scans]}


@app.post("/api/scans")
def create_scan(req: CreateScanRequest) -> dict[str, Any]:
    root = _resolve_project_root(req.project_path)
    scan_id = _new_scan_id()
    now = _now_iso()
    scan = {
        "scan_id": scan_id,
        "name": req.name.strip() if req.name and req.name.strip() else f"Scan {now}",
        "project_path": _relative_project_path(root),
        "status": "pending",
        "step": req.step,
        "created_at": now,
        "updated_at": now,
        "started_at": None,
        "finished_at": None,
        "last_run_id": None,
        "audit_limit": req.audit_limit,
        "priority_chain_limit": req.priority_chain_limit,
        "audit_dry_run": req.audit_dry_run,
    }
    _write_scan(root, scan)
    return _hydrate_scan(root, scan)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, project_path: str = Query(...)) -> dict[str, Any]:
    root = _resolve_project_root(project_path)
    return _hydrate_scan(root, _require_scan(root, scan_id))


@app.patch("/api/scans/{scan_id}")
def update_scan(scan_id: str, req: UpdateScanRequest, project_path: str = Query(...)) -> dict[str, Any]:
    root = _resolve_project_root(project_path)
    scan = _require_scan(root, scan_id)
    # 兼容 Pydantic v1/v2：工作台只需要读取显式提交的扫描元信息字段。
    updates = req.dict(exclude_unset=True)
    for key, value in updates.items():
        if key == "name" and isinstance(value, str):
            value = value.strip() or scan.get("name") or scan_id
        scan[key] = value
    scan["updated_at"] = _now_iso()
    _write_scan(root, scan)
    return _hydrate_scan(root, scan)


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str, project_path: str = Query(...)) -> dict[str, Any]:
    root = _resolve_project_root(project_path)
    _require_scan(root, scan_id)
    scan_dir = _scan_dir(root, scan_id)
    if scan_dir.exists():
        shutil.rmtree(scan_dir)
    scans = [item for item in _read_scan_index(root) if item.get("scan_id") != scan_id]
    _write_scan_index(root, scans)
    return {"ok": True, "scan_id": scan_id}


@app.post("/api/scans/{scan_id}/start")
def start_scan(scan_id: str, req: StartScanRequest) -> dict[str, Any]:
    root = _resolve_project_root(req.project_path)
    scan = _require_scan(root, scan_id)

    if _running_for_scan(scan_id):
        raise HTTPException(status_code=409, detail="Scan is already running")

    # 启动前先计算并固化本次有效参数，避免前端输入 50 但后端仍使用旧 scan 默认值 20。
    for key in ("step", "audit_limit", "priority_chain_limit", "audit_dry_run"):
        value = getattr(req, key)
        if value is not None:
            scan[key] = value
    effective_priority_chain_limit = _positive_int_or_none(scan.get("priority_chain_limit"))
    effective_audit_limit = _positive_int_or_none(scan.get("audit_limit"))
    scan["priority_chain_limit"] = effective_priority_chain_limit
    scan["audit_limit"] = effective_audit_limit
    scan["audit_dry_run"] = bool(scan.get("audit_dry_run", False))

    run_id = f"run-{uuid.uuid4().hex[:12]}"
    artifacts_dir = _scan_artifacts_dir(root, scan_id)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    log_path = _scan_dir(root, scan_id) / CONSOLE_FILENAME
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")

    cmd = [
        sys.executable,
        str(BACKEND_DIR / "main.py"),
        _relative_project_path(root),
        "--artifacts-dir",
        str(artifacts_dir),
    ]
    if effective_priority_chain_limit is not None:
        cmd.extend(["--priority-chain-limit", str(effective_priority_chain_limit)])
    if effective_audit_limit is not None:
        cmd.extend(["--audit-limit", str(effective_audit_limit)])
    if scan.get("audit_dry_run"):
        cmd.append("--audit-dry-run")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    # 扫描记录只负责调度 CLI；核心扫描逻辑仍以 backend/main.py 和 workflow.py 为权威入口。
    log_handle = log_path.open("a", encoding="utf-8", errors="replace")
    process = subprocess.Popen(
        cmd,
        cwd=str(WORKSPACE_ROOT),
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    run = RunProcess(
        run_id=run_id,
        scan_id=scan_id,
        project_path=_relative_project_path(root),
        process=process,
        log_path=log_path,
        cmd=cmd,
        priority_chain_limit=effective_priority_chain_limit,
        audit_limit=effective_audit_limit,
        audit_dry_run=bool(scan.get("audit_dry_run")),
    )
    RUNS[run_id] = run

    now = _now_iso()
    scan.update(
        {
            "status": "running",
            "started_at": now,
            "finished_at": None,
            "updated_at": now,
            "last_run_id": run_id,
            "effective_command": cmd,
        }
    )
    _write_scan(root, scan)
    threading.Thread(target=_watch_run, args=(run_id, log_handle), daemon=True).start()
    return {
        "run_id": run_id,
        "scan_id": scan_id,
        "status": "running",
        "cmd": cmd,
        "priority_chain_limit": effective_priority_chain_limit,
        "audit_limit": effective_audit_limit,
        "audit_dry_run": bool(scan.get("audit_dry_run")),
    }


@app.post("/api/scans/{scan_id}/stop")
def stop_scan(scan_id: str, project_path: str = Query(...)) -> dict[str, Any]:
    root = _resolve_project_root(project_path)
    run = _running_for_scan(scan_id)
    if run:
        run.process.terminate()
        run.status = "killed"
        run.last_message = "扫描已手动停止"
    scan = _require_scan(root, scan_id)
    scan.update({"status": "killed", "finished_at": _now_iso(), "updated_at": _now_iso()})
    _write_scan(root, scan)
    return {"ok": True, "scan_id": scan_id}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    _refresh_run(run)
    return _run_dict(run)


@app.get("/api/runs/{run_id}/stream")
async def stream_run(run_id: str) -> StreamingResponse:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    async def events():
        pos = 0
        while True:
            if run.log_path.exists():
                with run.log_path.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(pos)
                    chunk = handle.read()
                    pos = handle.tell()
                if chunk:
                    # 工作台不再展示原始控制台日志，只保留最后一条文本用于失败提示。
                    last_line = _last_non_empty_line(chunk)
                    if last_line:
                        run.last_message = _humanize_run_message(last_line)
            _refresh_run(run)
            yield f"data: {json.dumps({'type': 'status', **_run_dict(run)}, ensure_ascii=False)}\n\n"
            if run.status not in {"pending", "running"}:
                yield f"data: {json.dumps({'type': 'end'}, ensure_ascii=False)}\n\n"
                break
            await asyncio.sleep(1)

    return StreamingResponse(events(), media_type="text/event-stream")


@app.get("/api/scans/{scan_id}/console")
def read_scan_console(scan_id: str, project_path: str = Query(...), tail: int = Query(4000, ge=1, le=20000)) -> dict[str, Any]:
    root = _resolve_project_root(project_path)
    _require_scan(root, scan_id)
    path = _scan_dir(root, scan_id) / CONSOLE_FILENAME
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    lines = text.splitlines()
    return {"path": str(path), "size": len(text), "lines": lines[-tail:]}


@app.get("/api/artifacts/json")
def read_json_artifact(
    project_path: str = Query(...),
    filename: str = Query(...),
    scan_id: str | None = Query(None),
) -> dict[str, Any]:
    path = _artifact_path(project_path, filename, scan_id)
    data = _read_json(path)
    return {"path": str(path), "size": path.stat().st_size, "mtime": path.stat().st_mtime, "data": data}


@app.get("/api/artifacts/jsonl")
def read_jsonl_artifact(
    project_path: str = Query(...),
    filename: str = Query(...),
    scan_id: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    path = _artifact_path(project_path, filename, scan_id)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    total = len([line for line in lines if line.strip()])
    items = []
    for line in lines[offset : offset + limit]:
        if not line.strip():
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            items.append({"raw": line})
    return {"path": str(path), "offset": offset, "limit": limit, "total": total, "items": items}


@app.get("/api/artifacts/markdown")
def read_markdown_artifact(
    project_path: str = Query(...),
    filename: str = Query(...),
    scan_id: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    keyword: str | None = Query(None),
) -> dict[str, Any]:
    path = _artifact_path(project_path, filename, scan_id)
    text = path.read_text(encoding="utf-8", errors="replace")
    head, sections = _split_markdown_sections(text)
    if keyword:
        needle = keyword.lower()
        sections = [section for section in sections if needle in section.lower()]
    return {
        "path": str(path),
        "head": head,
        "sections": sections[offset : offset + limit],
        "offset": offset,
        "limit": limit,
        "total": len(sections),
    }


@app.get("/api/artifacts/audit")
def read_audit_agent(
    project_path: str = Query(...),
    scan_id: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(40, ge=1, le=200),
    severity: str | None = Query(None),
    verdict: str | None = Query(None),
    keyword: str | None = Query(None),
    vulnerability_type: str | None = Query(None),
) -> dict[str, Any]:
    path = _artifact_path(project_path, "audit_agent.json", scan_id)
    data = _read_json(path)
    audits = data.get("audits") or data.get("findings") or []
    if not isinstance(audits, list):
        audits = []
    # 审计 Agent 的结果可能没有携带 vulnerability_type；这里回连 CallScan priority chains，
    # 用 chain_id / analysis_id 补齐漏洞类型和 sink 位置，避免前端全部显示 unknown。
    chain_index = _load_priority_chain_index(_artifact_path(project_path, "callscan_chains.priority.jsonl", scan_id))
    filtered = [
        _normalize_audit_item(item, index, chain_index)
        for index, item in enumerate(audits)
        if isinstance(item, dict)
    ]
    if severity:
        filtered = [item for item in filtered if str(item.get("severity", "")).lower() == severity.lower()]
    if verdict:
        filtered = [item for item in filtered if _verdict_bucket(item.get("verdict")) == _verdict_bucket(verdict)]
    if vulnerability_type:
        filtered = [
            item
            for item in filtered
            if str(item.get("vulnerability_type", "")).lower() == vulnerability_type.lower()
        ]
    if keyword:
        needle = keyword.lower()
        filtered = [item for item in filtered if needle in json.dumps(item, ensure_ascii=False).lower()]

    head = dict(data)
    head.pop("audits", None)
    head.pop("findings", None)
    head["summary"] = _audit_summary_from_items(filtered, data.get("summary"))
    return {
        "path": str(path),
        "head": head,
        "findings": filtered[offset : offset + limit],
        "offset": offset,
        "limit": limit,
        "total": len(filtered),
    }


def _iter_project_roots() -> list[Path]:
    if not REPO_CODE_DIR.exists():
        return []
    roots: set[Path] = set()
    for child in REPO_CODE_DIR.iterdir():
        if not child.is_dir():
            continue
        if _looks_like_project_root(child):
            roots.add(child)
        for grandchild in child.iterdir():
            if grandchild.is_dir() and not grandchild.name.startswith(".") and _looks_like_project_root(grandchild):
                roots.add(grandchild)
        nested = [path for path in child.rglob(".defectmine") if path.is_dir()]
        for artifacts_dir in nested:
            roots.add(artifacts_dir.parent)
    return sorted(roots)


def _looks_like_project_root(path: Path) -> bool:
    if (path / ARTIFACTS_DIRNAME).is_dir():
        return True
    markers = {
        ".git",
        "composer.json",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "pom.xml",
        "build.gradle",
        "go.mod",
        "Cargo.toml",
        "README.md",
        "README",
    }
    return any((path / marker).exists() for marker in markers)


def _project_summary(root: Path) -> dict[str, Any]:
    artifacts = _artifact_stats(_artifacts_dir(root))
    scans = [_hydrate_scan(root, scan) for scan in _read_scan_index(root)]
    latest = scans[0] if scans else None
    return {
        "project_path": _relative_project_path(root),
        "project_root": str(root),
        "name": _project_display_name(root),
        "has_artifacts": bool(artifacts),
        "artifacts": artifacts,
        "scan_count": len(scans),
        "latest_scan": latest,
        "audit_summary": _project_audit_summary(root, latest),
        "callscan_summary": _callscan_summary(root, latest),
    }


def _project_display_name(root: Path) -> str:
    profile = _maybe_read_json(_artifacts_dir(root) / "treescan_agent.json")
    if isinstance(profile, dict):
        name = profile.get("project_name")
        if isinstance(name, str) and name.strip() and name != "unknown":
            return name.strip()
    return root.name


def _project_audit_summary(root: Path, latest: dict[str, Any] | None) -> dict[str, Any]:
    if latest and latest.get("audit_summary"):
        return latest["audit_summary"]
    return _audit_summary_for_path(_artifacts_dir(root) / "audit_agent.json")


def _callscan_summary(root: Path, latest: dict[str, Any] | None) -> dict[str, Any]:
    if latest and latest.get("callscan_summary"):
        return latest["callscan_summary"]
    path = _artifacts_dir(root) / "callscan_chains.priority.jsonl"
    return {"candidate_chains": _count_jsonl(path)}


def _artifact_stats(artifacts_dir: Path) -> dict[str, Any]:
    stats = {}
    if not artifacts_dir.exists():
        return stats
    for name in CORE_ARTIFACTS:
        path = artifacts_dir / name
        if path.is_file():
            stat = path.stat()
            stats[name] = {"size": stat.st_size, "mtime": stat.st_mtime}
    return stats


def _hydrate_scan(root: Path, scan: dict[str, Any]) -> dict[str, Any]:
    scan = dict(scan)
    artifacts_dir = _scan_artifacts_dir(root, scan["scan_id"])
    scan["artifacts_dir"] = str(artifacts_dir)
    scan["artifacts"] = _artifact_stats(artifacts_dir)
    scan["audit_summary"] = _audit_summary_for_path(artifacts_dir / "audit_agent.json")
    scan["callscan_summary"] = {"candidate_chains": _count_jsonl(artifacts_dir / "callscan_chains.priority.jsonl")}
    return scan


def _read_scan_index(root: Path) -> list[dict[str, Any]]:
    index_path = _scans_dir(root) / SCAN_INDEX_FILENAME
    if not index_path.is_file():
        return []
    data = _maybe_read_json(index_path)
    if not isinstance(data, list):
        return []
    return sorted([item for item in data if isinstance(item, dict)], key=lambda item: str(item.get("created_at", "")), reverse=True)


def _write_scan_index(root: Path, scans: list[dict[str, Any]]) -> None:
    path = _scans_dir(root) / SCAN_INDEX_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scans, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_scan(root: Path, scan: dict[str, Any]) -> None:
    scan_dir = _scan_dir(root, scan["scan_id"])
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / SCAN_META_FILENAME).write_text(json.dumps(scan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    scans = [item for item in _read_scan_index(root) if item.get("scan_id") != scan["scan_id"]]
    scans.insert(0, scan)
    _write_scan_index(root, scans)


def _require_scan(root: Path, scan_id: str) -> dict[str, Any]:
    meta_path = _scan_dir(root, scan_id) / SCAN_META_FILENAME
    data = _maybe_read_json(meta_path)
    if isinstance(data, dict):
        return data
    for scan in _read_scan_index(root):
        if scan.get("scan_id") == scan_id:
            return scan
    raise HTTPException(status_code=404, detail="Scan not found")


def _watch_run(run_id: str, log_handle: Any) -> None:
    run = RUNS[run_id]
    return_code = run.process.wait()
    log_handle.close()
    run.return_code = return_code
    run.finished_at = time.time()
    if run.status != "killed":
        run.status = "done" if return_code == 0 else "error"
    if run.status == "done":
        run.last_message = "扫描完成，产物已写入本次扫描目录"
    elif run.status == "error":
        run.error_message = _tail_error_message(run.log_path)
        run.last_message = run.error_message or "扫描失败，请查看 console.log 文件"

    root = _resolve_project_root(run.project_path)
    if run.status == "done":
        _mirror_scan_artifacts_to_root(root, run.scan_id)
    scan = _require_scan(root, run.scan_id)
    scan.update(
        {
            "status": run.status,
            "finished_at": _now_iso(),
            "updated_at": _now_iso(),
            "return_code": return_code,
            "error_message": run.error_message,
        }
    )
    _write_scan(root, scan)


def _refresh_run(run: RunProcess) -> None:
    if run.status == "running" and run.process.poll() is not None:
        run.return_code = run.process.returncode
        run.finished_at = time.time()
        run.status = "done" if run.return_code == 0 else "error"
        if run.status == "error" and not run.error_message:
            run.error_message = _tail_error_message(run.log_path)
            run.last_message = run.error_message or "扫描失败，请查看 console.log 文件"


def _run_dict(run: RunProcess) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "scan_id": run.scan_id,
        "project_path": run.project_path,
        "status": run.status,
        "return_code": run.return_code,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "log_path": str(run.log_path),
        "elapsed_seconds": round((run.finished_at or time.time()) - run.started_at, 2),
        "last_message": run.last_message,
        "error_message": run.error_message,
        "cmd": run.cmd,
        "priority_chain_limit": run.priority_chain_limit,
        "audit_limit": run.audit_limit,
        "audit_dry_run": run.audit_dry_run,
    }


def _running_for_scan(scan_id: str) -> RunProcess | None:
    for run in RUNS.values():
        _refresh_run(run)
        if run.scan_id == scan_id and run.status == "running":
            return run
    return None


def _artifact_path(project_path: str, filename: str, scan_id: str | None) -> Path:
    if filename not in CORE_ARTIFACTS:
        raise HTTPException(status_code=400, detail="Unsupported artifact filename")
    root = _resolve_project_root(project_path)
    base = _scan_artifacts_dir(root, scan_id) if scan_id else _artifacts_dir(root)
    path = (base / filename).resolve()
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Artifact not found: {filename}")
    return path


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Invalid JSON artifact: {path.name}") from exc


def _maybe_read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _audit_summary_for_path(path: Path) -> dict[str, Any]:
    data = _maybe_read_json(path)
    if not isinstance(data, dict):
        return _empty_audit_summary()
    audits = data.get("audits") or data.get("findings") or []
    if not isinstance(audits, list):
        audits = []
    chain_index = _load_priority_chain_index(path.with_name("callscan_chains.priority.jsonl"))
    items = [
        _normalize_audit_item(item, index, chain_index)
        for index, item in enumerate(audits)
        if isinstance(item, dict)
    ]
    return _audit_summary_from_items(items, data.get("summary"))


def _audit_summary_from_items(items: list[dict[str, Any]], existing: Any = None) -> dict[str, Any]:
    summary = _empty_audit_summary()
    for item in items:
        verdict = _verdict_bucket(item.get("verdict"))
        vuln = str(item.get("vulnerability_type") or item.get("vuln_type") or "unknown")
        severity = str(item.get("severity") or "unknown").lower()
        summary["total_audited"] += 1
        if verdict == "vulnerable":
            summary["vulnerable"] += 1
        elif verdict == "safe":
            summary["safe"] += 1
        elif verdict == "uncertain":
            summary["uncertain"] += 1
        elif verdict == "error":
            summary["errors"] += 1
        else:
            summary["errors"] += 1
        summary["by_vulnerability"][vuln] = summary["by_vulnerability"].get(vuln, 0) + 1
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

    if isinstance(existing, dict):
        for key in ("total_chains", "candidate_chains"):
            if key in existing:
                summary[key] = existing[key]
        if "chains" in existing and not summary.get("total_chains"):
            summary["total_chains"] = existing["chains"]
        if summary["total_audited"] == 0 and "total_audited" in existing:
            summary["total_audited"] = existing.get("total_audited", 0)
        if summary["total_audited"] == 0 and "audited" in existing:
            summary["total_audited"] = existing.get("audited", 0)
            for key in ("vulnerable", "uncertain", "safe", "errors"):
                if key in existing:
                    summary[key] = int(existing.get(key, 0) or 0)
            if isinstance(existing.get("by_vulnerability"), dict):
                summary["by_vulnerability"] = {str(name): int(count or 0) for name, count in existing["by_vulnerability"].items()}
            if isinstance(existing.get("by_severity"), dict):
                summary["by_severity"] = {str(name): int(count or 0) for name, count in existing["by_severity"].items()}
        if isinstance(existing.get("cost"), dict):
            summary["cost"] = existing["cost"]
    summary["total_chains"] = summary.get("total_chains") or summary["total_audited"]
    return summary


def _empty_audit_summary() -> dict[str, Any]:
    return {
        "total_chains": 0,
        "total_audited": 0,
        "vulnerable": 0,
        "uncertain": 0,
        "safe": 0,
        "errors": 0,
        "by_vulnerability": {},
        "by_severity": {},
    }


def _merge_audit_summaries(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    merged = _empty_audit_summary()
    for summary in summaries:
        for key in ("total_chains", "total_audited", "vulnerable", "uncertain", "safe", "errors"):
            merged[key] += int(summary.get(key, 0) or 0)
        for key in ("by_vulnerability", "by_severity"):
            for name, count in (summary.get(key) or {}).items():
                merged[key][name] = merged[key].get(name, 0) + int(count or 0)
    return merged


def _normalize_audit_item(
    item: dict[str, Any],
    index: int,
    chain_index: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    normalized = dict(item)
    normalized.setdefault("index", index)
    meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
    normalized["chain_id"] = str(item.get("chain_id") or meta.get("chain_id") or item.get("analysis_id") or f"audit-{index + 1}")
    normalized["analysis_id"] = str(item.get("analysis_id") or meta.get("analysis_id") or normalized["chain_id"])
    chain = (chain_index or {}).get(str(normalized.get("chain_id"))) or (chain_index or {}).get(str(normalized.get("analysis_id")))
    chain_sink = chain.get("sink", {}) if isinstance(chain, dict) and isinstance(chain.get("sink"), dict) else {}
    item_sink = item.get("sink") if isinstance(item.get("sink"), dict) else {}
    rank = chain.get("rank", {}) if isinstance(chain, dict) and isinstance(chain.get("rank"), dict) else {}
    inferred_vuln = _first_known_value(
        item.get("vulnerability_type"),
        item.get("vuln_type"),
        item.get("type"),
        chain.get("vulnerability_type") if isinstance(chain, dict) else None,
        item_sink.get("vulnerability_type"),
        item_sink.get("vulnerability"),
        chain_sink.get("vulnerability_type"),
        chain_sink.get("vulnerability"),
        item.get("cwe_guess"),
        default="unknown",
    )
    normalized["vulnerability_type"] = str(inferred_vuln)
    if item_sink and not normalized.get("sink"):
        normalized["sink"] = item_sink
    elif chain_sink and (not isinstance(normalized.get("sink"), dict) or not normalized.get("sink", {}).get("file")):
        normalized["sink"] = chain_sink
    if chain and "callscan_chain" not in normalized:
        normalized["callscan_chain"] = {
            "path_id": chain.get("path_id"),
            "analysis_id": chain.get("analysis_id"),
            "sink": chain.get("sink"),
            "entry": chain.get("entry"),
            "rank": chain.get("rank"),
        }
    verdict = _verdict_bucket(item.get("verdict"))
    if str(meta.get("status", "")).lower() == "error":
        verdict = "error"
    normalized["verdict"] = verdict if verdict != "unknown" else "uncertain"
    severity = _normalize_severity(
        _first_known_value(
            item.get("severity"),
            meta.get("severity"),
            rank.get("risk_level"),
            rank.get("severity"),
            item_sink.get("severity"),
            chain_sink.get("severity"),
            default="unknown",
        )
    )
    normalized["severity"] = severity
    normalized["confidence_label"] = item.get("confidence_label") or _confidence_label(item.get("confidence"))
    if not normalized.get("title"):
        normalized["title"] = _audit_title_from_item(normalized)
    return normalized


def _load_priority_chain_index(path: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return index
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        for key in (item.get("path_id"), item.get("analysis_id")):
            if key:
                index[str(key)] = item
    return index


def _verdict_bucket(value: Any) -> str:
    verdict = str(value or "").lower()
    if verdict in {"vulnerable", "confirmed", "true_positive"}:
        return "vulnerable"
    if verdict in {"not_vulnerable", "safe", "false_positive"}:
        return "safe"
    if verdict in {"needs_review", "inconclusive", "uncertain", "suspicious"}:
        return "uncertain"
    if verdict == "error":
        return "error"
    return "unknown"


def _normalize_severity(value: Any) -> str:
    severity = str(value or "unknown").strip().lower()
    return severity if severity in {"critical", "high", "medium", "low", "info", "unknown"} else "unknown"


def _first_known_value(*values: Any, default: str = "unknown") -> Any:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"unknown", "none", "null"}:
            return value
    return default


def _confidence_label(value: Any) -> str:
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"high", "medium", "low"}:
            return lowered
        try:
            value = float(lowered)
        except ValueError:
            return "low"
    if isinstance(value, (int, float)):
        confidence = float(value)
        if confidence >= 0.75:
            return "high"
        if confidence >= 0.45:
            return "medium"
    return "low"


def _audit_title_from_item(item: dict[str, Any]) -> str:
    sink = item.get("sink") if isinstance(item.get("sink"), dict) else {}
    vuln = str(item.get("vulnerability_type") or item.get("cwe_guess") or "unknown")
    if sink.get("file"):
        return f"{vuln} @ {sink.get('file')}:{sink.get('line') or 0}"
    return vuln


def _split_markdown_sections(text: str) -> tuple[str, list[str]]:
    marker = "====="
    if marker not in text:
        return "", [text] if text.strip() else []
    chunks = text.split(marker)
    head = chunks[0].strip()
    sections = [f"{marker}{chunk}".strip() for chunk in chunks[1:] if chunk.strip()]
    return head, sections


def _count_jsonl(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def _mirror_scan_artifacts_to_root(root: Path, scan_id: str) -> None:
    source_dir = _scan_artifacts_dir(root, scan_id)
    target_dir = _artifacts_dir(root)
    if not source_dir.is_dir():
        return
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in CORE_ARTIFACTS:
        source = source_dir / name
        if source.is_file():
            shutil.copy2(source, target_dir / name)


def _positive_int_or_none(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _last_non_empty_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        cleaned = line.strip()
        if cleaned:
            return cleaned
    return ""


def _tail_error_message(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines[-80:]):
        cleaned = line.strip()
        if not cleaned:
            continue
        if _is_ignorable_runtime_warning(cleaned):
            continue
        if "error" in cleaned.lower() or "traceback" in cleaned.lower() or "exception" in cleaned.lower():
            return cleaned[:500]
    return _last_non_empty_line("\n".join(lines[-20:]))[:500]


def _humanize_run_message(line: str) -> str:
    lowered = line.lower()
    if _is_ignorable_runtime_warning(line):
        return "扫描运行中"
    if "treescan" in lowered:
        return "TreeScan 正在生成项目画像"
    if "callscan" in lowered or "sink" in lowered:
        return "CallScan 正在搜索 sink 并构建调用链"
    if "audit" in lowered or "scanner" in lowered:
        return "Scanner 正在审计优先调用链"
    if "error" in lowered or "traceback" in lowered or "exception" in lowered:
        return line[:500]
    return "扫描运行中"


def _is_ignorable_runtime_warning(line: str) -> bool:
    lowered = line.lower()
    return (
        "litellm:warning" in lowered
        and "sagemaker-runtime" in lowered
        and "botocore" in lowered
    )


def _resolve_project_root(project_path: str) -> Path:
    raw = Path(project_path).expanduser()
    if raw.is_absolute():
        root = raw.resolve()
    else:
        root = (REPO_CODE_DIR / raw).resolve()
    try:
        root.relative_to(REPO_CODE_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Project path must stay under repo_code") from exc
    if not root.is_dir():
        raise HTTPException(status_code=404, detail=f"Project not found: {project_path}")
    return root


def _relative_project_path(root: Path) -> str:
    return root.resolve().relative_to(REPO_CODE_DIR.resolve()).as_posix()


def _artifacts_dir(root: Path) -> Path:
    return root / ARTIFACTS_DIRNAME


def _scans_dir(root: Path) -> Path:
    return _artifacts_dir(root) / SCANS_DIRNAME


def _scan_dir(root: Path, scan_id: str) -> Path:
    return _scans_dir(root) / scan_id


def _scan_artifacts_dir(root: Path, scan_id: str | None) -> Path:
    return _scan_dir(root, scan_id) / "artifacts" if scan_id else _artifacts_dir(root)


def _new_scan_id() -> str:
    return f"scan-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")

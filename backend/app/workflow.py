"""Workflow orchestration for the DefectMine scanning MVP.

Default MVP pipeline:
TreeScan -> CallScan -> Scanner Audit
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app.callscan import CallScanResult, run_callscan
from app.scanner import AuditScannerResult, run_audit_scanner
from app.treescan import TreeScanResult, run_treescan


REPO_CODE_DIRNAME = "repo_code"
ARTIFACTS_DIRNAME = ".defectmine"
WORKFLOW_STATE_FILENAME = "workflow_state.json"

TreeScanRunner = Callable[..., TreeScanResult]
CallScanRunner = Callable[..., CallScanResult]
AuditScannerRunner = Callable[..., AuditScannerResult]
ProgressReporter = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class WorkflowContext:
    project_root: Path
    artifacts_dir: Path

    @classmethod
    def from_project(
        cls,
        project_path: str | Path,
        *,
        artifacts_dir: str | Path | None = None,
    ) -> "WorkflowContext":
        project_root = _resolve_project_root(project_path)
        return cls(
            project_root=project_root,
            artifacts_dir=_resolve_artifacts_dir(project_root, artifacts_dir),
        )

    def artifact_path(self, filename: str) -> Path:
        return self.artifacts_dir / filename

    def write_json(self, filename: str, data: Any) -> Path:
        path = self.artifact_path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(data, ensure_ascii=False, indent=2)
        path.write_text(text + "\n", encoding="utf-8")
        return path


@dataclass(frozen=True)
class WorkflowStage:
    name: str
    status: str
    elapsed_seconds: float
    artifacts: dict[str, str]
    summary: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "elapsed_seconds": self.elapsed_seconds,
            "artifacts": self.artifacts,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class WorkflowResult:
    root: Path
    project_absolute_path: Path
    artifacts_dir: Path
    treescan: TreeScanResult
    callscan: CallScanResult
    audit_scanner: AuditScannerResult
    stages: list[WorkflowStage]
    elapsed_seconds: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "project_absolute_path": str(self.project_absolute_path),
            "artifacts_dir": str(self.artifacts_dir),
            "elapsed_seconds": self.elapsed_seconds,
            "stages": [stage.as_dict() for stage in self.stages],
            "treescan": self.treescan.state_dict(),
            "callscan": self.callscan.state_dict(),
            "audit_scanner": self.audit_scanner.state_dict(),
        }


def run_workflow(
    project_path: str | Path,
    *,
    artifacts_dir: str | Path | None = None,
    persist: bool = True,
    treescan_runner: TreeScanRunner = run_treescan,
    callscan_runner: CallScanRunner = run_callscan,
    audit_scanner_runner: AuditScannerRunner = run_audit_scanner,
    priority_chain_limit: int = 20,
    audit_limit: int | None = None,
    enable_llm_audit: bool = True,
    enable_mcp_tools: bool = True,
    allow_active_poc: bool = False,
    progress_reporter: ProgressReporter | None = None,
) -> WorkflowResult:
    """Run the DefectMine MVP pipeline end to end."""
    workflow_started_at = time.perf_counter()
    context = WorkflowContext.from_project(project_path, artifacts_dir=artifacts_dir)
    total_steps = 3

    _report_progress(
        progress_reporter,
        {
            "event": "workflow_started",
            "project_path": str(project_path),
            "project_root": str(context.project_root),
            "artifacts_dir": str(context.artifacts_dir),
            "total_steps": total_steps,
            "priority_chain_limit": priority_chain_limit,
            "audit_limit": audit_limit,
        },
    )

    #----------- Step 1: TreeScan 扫描目录树并生成项目画像 ------------#
    treescan_stage, treescan_result = _run_treescan_stage(
        context,
        persist=persist,
        treescan_runner=treescan_runner,
        progress_reporter=progress_reporter,
        step_index=1,
        total_steps=total_steps,
    )

    #----------- Step 2: CallScan 搜索危险 sink 并生成优先审计队列 ------------#
    callscan_stage, callscan_result = _run_callscan_stage(
        context,
        persist=persist,
        callscan_runner=callscan_runner,
        progress_reporter=progress_reporter,
        step_index=2,
        total_steps=total_steps,
        priority_chain_limit=priority_chain_limit,
    )

    #----------- Step 3: Scanner Audit 审计优先调用链并生成 JSON/Markdown 报告 ------------#
    audit_stage, audit_result = _run_audit_scanner_stage(
        context,
        persist=persist,
        audit_scanner_runner=audit_scanner_runner,
        progress_reporter=progress_reporter,
        step_index=3,
        total_steps=total_steps,
        audit_limit=audit_limit,
        enable_llm_audit=enable_llm_audit,
        enable_mcp_tools=enable_mcp_tools,
        allow_active_poc=allow_active_poc,
    )

    result = WorkflowResult(
        root=treescan_result.root,
        project_absolute_path=context.project_root,
        artifacts_dir=context.artifacts_dir,
        treescan=treescan_result,
        callscan=callscan_result,
        audit_scanner=audit_result,
        stages=[treescan_stage, callscan_stage, audit_stage],
        elapsed_seconds=_elapsed_since(workflow_started_at),
    )

    if persist:
        context.write_json(WORKFLOW_STATE_FILENAME, result.as_dict())

    _report_progress(
        progress_reporter,
        {
            "event": "workflow_completed",
            "elapsed_seconds": result.elapsed_seconds,
            "artifacts_dir": str(result.artifacts_dir),
            "stages": [stage.as_dict() for stage in result.stages],
        },
    )
    return result


def _run_treescan_stage(
    context: WorkflowContext,
    *,
    persist: bool,
    treescan_runner: TreeScanRunner,
    progress_reporter: ProgressReporter | None,
    step_index: int,
    total_steps: int,
) -> tuple[WorkflowStage, TreeScanResult]:
    started_at = time.perf_counter()
    _report_progress(
        progress_reporter,
        {
            "event": "stage_started",
            "stage": "treescan",
            "step_index": step_index,
            "total_steps": total_steps,
            "title": "TreeScan",
            "message": "扫描目录树并生成项目画像",
        },
    )

    result = treescan_runner(
        context.project_root,
        artifacts_dir=context.artifacts_dir,
        persist=persist,
        progress_reporter=progress_reporter,
    )

    tree_files, tree_dirs = _count_tree(result.tree)
    stage = WorkflowStage(
        name="treescan",
        status="completed",
        elapsed_seconds=_elapsed_since(started_at),
        artifacts={
            "tree": str(context.artifact_path("tree.json")),
            "profile": str(context.artifact_path("treescan_agent.json")),
            "raw_profile": str(context.artifact_path("treescan_agent.raw.txt")),
        },
        summary={
            "files": tree_files,
            "dirs": tree_dirs,
            "profile": _profile_summary(result.profile),
        },
    )

    _report_progress(
        progress_reporter,
        {
            "event": "stage_completed",
            "stage": "treescan",
            "step_index": step_index,
            "total_steps": total_steps,
            "elapsed_seconds": stage.elapsed_seconds,
            "summary": stage.summary,
            "artifacts": stage.artifacts,
        },
    )
    return stage, result


def _run_callscan_stage(
    context: WorkflowContext,
    *,
    persist: bool,
    callscan_runner: CallScanRunner,
    progress_reporter: ProgressReporter | None,
    step_index: int,
    total_steps: int,
    priority_chain_limit: int,
) -> tuple[WorkflowStage, CallScanResult]:
    started_at = time.perf_counter()
    _report_progress(
        progress_reporter,
        {
            "event": "stage_started",
            "stage": "callscan",
            "step_index": step_index,
            "total_steps": total_steps,
            "title": "CallScan",
            "message": "搜索危险 sink 并生成优先审计队列",
        },
    )

    result = callscan_runner(
        context.project_root,
        artifacts_dir=context.artifacts_dir,
        persist=persist,
        progress_reporter=progress_reporter,
        priority_chain_limit=priority_chain_limit,
    )
    summary = result.report.get("summary", {})
    stage = WorkflowStage(
        name="callscan",
        status="completed",
        elapsed_seconds=_elapsed_since(started_at),
        artifacts={
            "report": str(context.artifact_path("callscan_agent.json")),
            "priority_chains": str(context.artifact_path("callscan_chains.priority.jsonl")),
        },
        summary={
            "sink_hits": summary.get("sink_hits", 0),
            "sink_analyses": summary.get("sink_analyses", 0),
            "priority_chains": summary.get("priority_chains", 0),
            "priority_chain_limit": priority_chain_limit,
            "mcp_tasks": summary.get("mcp_tasks", 0),
        },
    )

    _report_progress(
        progress_reporter,
        {
            "event": "stage_completed",
            "stage": "callscan",
            "step_index": step_index,
            "total_steps": total_steps,
            "elapsed_seconds": stage.elapsed_seconds,
            "summary": stage.summary,
            "artifacts": stage.artifacts,
        },
    )
    return stage, result


def _run_audit_scanner_stage(
    context: WorkflowContext,
    *,
    persist: bool,
    audit_scanner_runner: AuditScannerRunner,
    progress_reporter: ProgressReporter | None,
    step_index: int,
    total_steps: int,
    audit_limit: int | None,
    enable_llm_audit: bool,
    enable_mcp_tools: bool,
    allow_active_poc: bool,
) -> tuple[WorkflowStage, AuditScannerResult]:
    started_at = time.perf_counter()
    _report_progress(
        progress_reporter,
        {
            "event": "stage_started",
            "stage": "audit",
            "step_index": step_index,
            "total_steps": total_steps,
            "title": "Scanner Audit",
            "message": "审计优先调用链并生成报告",
        },
    )

    result = audit_scanner_runner(
        context.project_root,
        artifacts_dir=context.artifacts_dir,
        audit_limit=audit_limit,
        persist=persist,
        allow_active_poc=allow_active_poc,
        enable_llm_audit=enable_llm_audit,
        enable_mcp_tools=enable_mcp_tools,
        progress_reporter=progress_reporter,
    )
    summary = result.report.get("summary", {})
    stage = WorkflowStage(
        name="audit",
        status="completed",
        elapsed_seconds=_elapsed_since(started_at),
        artifacts={
            "report": str(context.artifact_path("audit_agent.json")),
            "markdown": str(context.artifact_path("audit_findings.md")),
        },
        summary={
            "chains": summary.get("chains", 0),
            "audited": summary.get("audited", 0),
            "audit_limit": audit_limit,
            "vulnerable": summary.get("vulnerable", 0),
            "not_vulnerable": summary.get("not_vulnerable", 0),
            "needs_review": summary.get("needs_review", 0),
            "inconclusive": summary.get("inconclusive", 0),
            "errors": summary.get("errors", 0),
        },
    )

    _report_progress(
        progress_reporter,
        {
            "event": "stage_completed",
            "stage": "audit",
            "step_index": step_index,
            "total_steps": total_steps,
            "elapsed_seconds": stage.elapsed_seconds,
            "summary": stage.summary,
            "artifacts": stage.artifacts,
        },
    )
    return stage, result


def _count_tree(node: dict[str, Any]) -> tuple[int, int]:
    if "summary" in node:
        summary = node["summary"]
        return summary.get("total_files", 0), summary.get("total_dirs", 0)
    if "tree" in node:
        return _count_tree(node["tree"])

    files = len(node.get("files", []))
    dirs = 0
    for child in node.get("dirs", {}).values():
        dirs += 1
        child_files, child_dirs = _count_tree(child)
        files += child_files
        dirs += child_dirs
    return files, dirs


def _profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    stack = profile.get("technology_stack", {})
    if not isinstance(stack, dict):
        stack = {}

    confidence = profile.get("confidence", {})
    if not isinstance(confidence, dict):
        confidence = {}

    return {
        "project_name": profile.get("project_name", "unknown"),
        "project_function": profile.get("project_function", "unknown"),
        "project_type": profile.get("project_type", "unknown"),
        "project_summary": profile.get("project_summary", ""),
        "project_understanding": profile.get("project_understanding", {}),
        "scanner_hints": profile.get("scanner_hints", {}),
        "architecture_style": profile.get("architecture_style", []),
        "backend": stack.get("backend", []),
        "frontend": stack.get("frontend", []),
        "database": stack.get("database", stack.get("data", [])),
        "confidence": confidence,
    }


def _elapsed_since(started_at: float) -> float:
    return round(time.perf_counter() - started_at, 4)


def _report_progress(
    progress_reporter: ProgressReporter | None,
    payload: dict[str, Any],
) -> None:
    if progress_reporter is None:
        return
    progress_reporter(payload)


def _resolve_project_root(project_path: str | Path) -> Path:
    raw_path = Path(project_path).expanduser()
    if raw_path.is_absolute():
        return _validate_project_root(raw_path.resolve())

    workspace_root = _workspace_root()
    if raw_path.parts and raw_path.parts[0] == REPO_CODE_DIRNAME:
        repo_candidate = workspace_root / raw_path
    else:
        repo_candidate = workspace_root / REPO_CODE_DIRNAME / raw_path

    cwd_candidate = (Path.cwd() / raw_path).resolve()
    for candidate in (repo_candidate, cwd_candidate):
        if candidate.exists():
            return _validate_project_root(candidate.resolve())

    return _validate_project_root(repo_candidate.resolve())


def _resolve_artifacts_dir(
    project_root: Path,
    artifacts_dir: str | Path | None,
) -> Path:
    if artifacts_dir is None:
        return (project_root / ARTIFACTS_DIRNAME).resolve()

    path = Path(artifacts_dir).expanduser()
    if not path.is_absolute():
        path = project_root / path
    return path.resolve()


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _validate_project_root(path: Path) -> Path:
    if not path.exists():
        raise FileNotFoundError(f"Project root does not exist: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"Project root is not a directory: {path}")
    return path

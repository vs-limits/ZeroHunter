"""Helpers for .defectmine artifacts and specific scoped runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.scanner.tree import resolve_scan_root

ARTIFACTS_DIRNAME = ".defectmine"
SPECIFIC_DIRNAME = "specific"
RUN_META_FILENAME = "run_meta.json"


@dataclass(frozen=True)
class RunScope:
    project_path: str
    project_root: Path
    artifacts_dir: Path
    mode: str = "project"
    run_id: str | None = None
    target_rel_dir: str | None = None
    target_abs_dir: Path | None = None

    @property
    def root_artifacts_dir(self) -> Path:
        return self.project_root / ARTIFACTS_DIRNAME

    @property
    def run_meta_path(self) -> Path | None:
        if self.mode != "specific" or not self.run_id:
            return None
        return self.artifacts_dir / RUN_META_FILENAME

    def contains_rel_path(self, rel_path: str) -> bool:
        if self.mode != "specific":
            return True

        target = self.target_rel_dir or "."
        if target == ".":
            return True

        normalized = _normalize_rel_path(rel_path)
        return normalized == target or normalized.startswith(f"{target}/")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "run_id": self.run_id,
            "target_rel_dir": self.target_rel_dir,
            "target_abs_dir": str(self.target_abs_dir) if self.target_abs_dir else None,
            "artifacts_dir": str(self.artifacts_dir),
        }


def create_specific_run(project_path: str, target_rel_dir: str) -> RunScope:
    project_root = resolve_scan_root(project_path)
    root_artifacts_dir = project_root / ARTIFACTS_DIRNAME
    specific_root = root_artifacts_dir / SPECIFIC_DIRNAME
    root_artifacts_dir.mkdir(parents=True, exist_ok=True)
    specific_root.mkdir(parents=True, exist_ok=True)

    target_abs_dir, normalized_rel_dir = _resolve_target_dir(project_root, target_rel_dir)
    run_id = _new_run_id(specific_root)
    artifacts_dir = specific_root / run_id
    artifacts_dir.mkdir(parents=True, exist_ok=False)

    created_at = datetime.now().astimezone().isoformat(timespec="seconds")
    metadata = {
        "run_id": run_id,
        "project_path": project_path,
        "project_root": str(project_root),
        "target_rel_dir": normalized_rel_dir,
        "target_abs_dir": str(target_abs_dir),
        "created_at": created_at,
        "mode": "specific",
    }
    (artifacts_dir / RUN_META_FILENAME).write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    return RunScope(
        project_path=project_path,
        project_root=project_root,
        artifacts_dir=artifacts_dir,
        mode="specific",
        run_id=run_id,
        target_rel_dir=normalized_rel_dir,
        target_abs_dir=target_abs_dir,
    )


def resolve_run_scope(project_path: str, run_id: str | None = None) -> RunScope:
    project_root = resolve_scan_root(project_path)
    root_artifacts_dir = project_root / ARTIFACTS_DIRNAME
    root_artifacts_dir.mkdir(parents=True, exist_ok=True)

    if not run_id:
        return RunScope(
            project_path=project_path,
            project_root=project_root,
            artifacts_dir=root_artifacts_dir,
        )

    # 新格式：.defectmine/scans/<scan_id>/scan.json
    scan_artifacts_dir = root_artifacts_dir / "scans" / run_id
    scan_meta_path = scan_artifacts_dir / "scan.json"
    if scan_meta_path.is_file():
        return _load_scan_scope(project_path, project_root, run_id, scan_artifacts_dir, scan_meta_path)

    return _load_specific_scope(project_path, project_root, run_id)


def _load_scan_scope(
    project_path: str,
    project_root: Path,
    scan_id: str,
    artifacts_dir: Path,
    meta_path: Path,
) -> RunScope:
    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    target = metadata.get("target") or {}
    rel_dir = target.get("rel_dir")

    if rel_dir:
        target_abs_dir = (project_root / rel_dir).resolve()
        try:
            target_abs_dir.relative_to(project_root.resolve())
        except ValueError as err:
            raise ValueError(f"扫描目标目录越界: {target_abs_dir}") from err
        if not target_abs_dir.is_dir():
            raise NotADirectoryError(f"扫描目标目录不存在: {target_abs_dir}")
        return RunScope(
            project_path=project_path,
            project_root=project_root,
            artifacts_dir=artifacts_dir,
            mode="specific",
            run_id=scan_id,
            target_rel_dir=rel_dir,
            target_abs_dir=target_abs_dir,
        )

    # 全仓库扫描：仍然走 project mode，但产物落在 scans/<id>/ 下
    return RunScope(
        project_path=project_path,
        project_root=project_root,
        artifacts_dir=artifacts_dir,
        mode="project",
        run_id=scan_id,
    )


def _load_specific_scope(
    project_path: str,
    project_root: Path,
    run_id: str,
) -> RunScope:
    artifacts_dir = project_root / ARTIFACTS_DIRNAME / SPECIFIC_DIRNAME / run_id
    meta_path = artifacts_dir / RUN_META_FILENAME
    if not meta_path.is_file():
        raise FileNotFoundError(f"Specific run metadata not found: {meta_path}")

    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    if metadata.get("mode") != "specific":
        raise ValueError(f"Invalid run mode in {meta_path}: {metadata.get('mode')!r}")
    if metadata.get("run_id") != run_id:
        raise ValueError(
            f"Specific run metadata mismatch in {meta_path}: "
            f"{metadata.get('run_id')!r} != {run_id!r}."
        )
    if metadata.get("project_path") != project_path:
        raise ValueError(
            f"Specific run {run_id} belongs to {metadata.get('project_path')!r}, "
            f"not {project_path!r}."
        )
    if Path(str(metadata.get("project_root") or "")).resolve() != project_root.resolve():
        raise ValueError(
            f"Specific run {run_id} project root does not match {project_root}."
        )

    target_rel_dir = str(metadata.get("target_rel_dir") or ".")
    target_abs_dir = Path(str(metadata.get("target_abs_dir") or project_root)).resolve()
    try:
        target_abs_dir.relative_to(project_root.resolve())
    except ValueError as err:
        raise ValueError(
            f"Specific target directory escapes project root: {target_abs_dir}"
        ) from err
    if not target_abs_dir.is_dir():
        raise NotADirectoryError(f"Specific target directory no longer exists: {target_abs_dir}")

    return RunScope(
        project_path=project_path,
        project_root=project_root,
        artifacts_dir=artifacts_dir,
        mode="specific",
        run_id=run_id,
        target_rel_dir=target_rel_dir,
        target_abs_dir=target_abs_dir,
    )


def _resolve_target_dir(project_root: Path, target_rel_dir: str) -> tuple[Path, str]:
    raw = (target_rel_dir or "").strip()
    if not raw:
        raise ValueError("target_rel_dir cannot be empty.")

    target_path = Path(raw)
    if target_path.is_absolute():
        raise ValueError("target_rel_dir must be a project-relative directory.")

    normalized_input = _normalize_rel_path(raw)
    if normalized_input.startswith("../") or normalized_input == "..":
        raise ValueError("target_rel_dir cannot escape the project root.")

    candidate = (project_root / target_path).resolve()
    project_root_resolved = project_root.resolve()
    try:
        relative = candidate.relative_to(project_root_resolved)
    except ValueError as err:
        raise ValueError("target_rel_dir must stay inside the project root.") from err

    if not candidate.exists():
        raise FileNotFoundError(f"Target directory not found: {candidate}")
    if not candidate.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {candidate}")

    normalized_rel = relative.as_posix() or "."
    return candidate, normalized_rel


def _normalize_rel_path(value: str) -> str:
    text = str(value or "").replace("\\", "/").strip("/")
    if not text:
        return "."
    return "/".join(part for part in text.split("/") if part and part != ".")


def _new_run_id(specific_root: Path) -> str:
    while True:
        run_id = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
        if not (specific_root / run_id).exists():
            return run_id

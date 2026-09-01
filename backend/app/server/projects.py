"""Project container and version management."""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from app.server import json_io
from app.server.paths import (
    ARTIFACTS_DIRNAME,
    PROJECT_META_DIRNAME,
    PROJECT_META_FILENAME,
    REPO_ROOT,
    VERSION_META_FILENAME,
    normalize_segment,
    parse_project_key,
    parse_project_path,
    project_container_dir,
    project_dir,
    project_metadata_path,
    specific_root,
    version_dir,
)


DEFAULT_VERSION_ROLE = "baseline"
VERSION_KINDS = {"manual", "copy", "local", "git"}
RESERVED_PROJECT_CHILDREN = {PROJECT_META_DIRNAME, "vulnerability"}
PROJECT_AUDIT_STATUSES = {"not_started", "scanning", "manual_review", "completed", "tracking"}


def list_projects(*, include_scan_summaries: bool = True) -> list[dict[str, Any]]:
    if not REPO_ROOT.is_dir():
        return []

    projects: list[dict[str, Any]] = []
    for source_dir in sorted(p for p in REPO_ROOT.iterdir() if p.is_dir()):
        if source_dir.name.startswith("."):
            continue
        for owner_dir in sorted(p for p in source_dir.iterdir() if p.is_dir()):
            if owner_dir.name.startswith("."):
                continue
            for repo_dir in sorted(p for p in owner_dir.iterdir() if p.is_dir()):
                if repo_dir.name.startswith("."):
                    continue
                projects.append(
                    _project_summary_from_dir(
                        source_dir.name,
                        owner_dir.name,
                        repo_dir.name,
                        repo_dir,
                        include_scan_summaries=include_scan_summaries,
                    )
                )
    return projects


def create_project(
    *,
    source: str,
    owner: str,
    repo: str,
    name: str = "",
    notes: str = "",
) -> dict[str, Any]:
    key = parse_project_key(source, owner, repo)
    container = project_container_dir(key.source, key.owner, key.repo)
    if container.exists() and any(container.iterdir()):
        raise FileExistsError(f"project already exists: {key.project_key}")
    container.mkdir(parents=True, exist_ok=True)
    meta = _project_meta_defaults(key.source, key.owner, key.repo)
    if name.strip():
        meta["name"] = name.strip()
    meta["notes"] = notes
    _write_json(project_metadata_path(key.source, key.owner, key.repo), meta)
    return _project_summary_from_dir(key.source, key.owner, key.repo, container)


def update_project(
    source: str,
    owner: str,
    repo: str,
    *,
    name: str | None = None,
    notes: str | None = None,
    description: str | None = None,
    tags: list[str] | None = None,
    audit_status: str | None = None,
    favorite: bool | None = None,
    project_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key = parse_project_key(source, owner, repo)
    container = project_container_dir(key.source, key.owner, key.repo)
    if not container.is_dir():
        raise FileNotFoundError(f"project does not exist: {key.project_key}")
    meta = _read_project_meta(key.source, key.owner, key.repo)
    if name is not None:
        meta["name"] = name.strip() or key.repo
    if notes is not None:
        meta["notes"] = notes
    if description is not None:
        meta["description"] = description
    if tags is not None:
        meta["tags"] = _string_list(tags)
    if audit_status is not None:
        status = audit_status.strip() or "not_started"
        if status not in PROJECT_AUDIT_STATUSES:
            raise ValueError("audit_status is invalid")
        meta["audit_status"] = status
    if favorite is not None:
        meta["favorite"] = bool(favorite)
    if project_profile is not None:
        meta["project_profile"] = _normalize_project_profile(project_profile)
    meta["updated_at"] = _now_iso()
    _write_json(project_metadata_path(key.source, key.owner, key.repo), meta)
    return _project_summary_from_dir(key.source, key.owner, key.repo, container)


def create_version(
    source: str,
    owner: str,
    repo: str,
    *,
    kind: str = "manual",
    version: str,
    name: str = "",
    notes: str = "",
    role: str = DEFAULT_VERSION_ROLE,
    overwrite: bool = False,
    source_version: str | None = None,
    local_path: str | None = None,
) -> dict[str, Any]:
    kind = (kind or "manual").strip().lower()
    if kind not in {"manual", "copy", "local"}:
        raise ValueError("kind must be manual, copy or local for this endpoint")
    key = parse_project_key(source, owner, repo)
    version_name = normalize_segment(version, field="version")
    container = _ensure_project_container(key.source, key.owner, key.repo)
    target = version_dir(key.source, key.owner, key.repo, version_name)
    _prepare_version_target(target, overwrite=overwrite)

    if kind == "manual":
        target.mkdir(parents=True, exist_ok=False)
    elif kind == "copy":
        if not source_version:
            raise ValueError("source_version is required for copy versions")
        src = version_dir(key.source, key.owner, key.repo, source_version)
        if not src.is_dir():
            raise FileNotFoundError(f"source version does not exist: {source_version}")
        _copy_code_tree(src, target)
    elif kind == "local":
        if not local_path:
            raise ValueError("local_path is required for local imports")
        src = Path(local_path).expanduser().resolve()
        if not src.is_dir():
            raise FileNotFoundError(f"local_path does not exist: {src}")
        _copy_code_tree(src, target)

    meta = _version_meta_defaults(
        key.source,
        key.owner,
        key.repo,
        version_name,
        kind=kind,
        name=name,
        notes=notes,
        role=role,
    )
    if kind == "copy":
        meta["copied_from"] = source_version
    if kind == "local":
        meta["local_path"] = str(Path(local_path or "").expanduser().resolve())
    _write_version_meta(target, meta)
    _ensure_project_metadata(key.source, key.owner, key.repo)
    return _version_summary(key.source, key.owner, key.repo, target)


def update_version(
    source: str,
    owner: str,
    repo: str,
    version: str,
    *,
    name: str | None = None,
    notes: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    key = parse_project_key(source, owner, repo)
    version_name = normalize_segment(version, field="version")
    path = version_dir(key.source, key.owner, key.repo, version_name)
    if not path.is_dir():
        raise FileNotFoundError(f"version does not exist: {version_name}")
    meta = _read_version_meta(path, key.source, key.owner, key.repo, version_name)
    if name is not None:
        meta["name"] = name.strip() or version_name
    if notes is not None:
        meta["notes"] = notes
    if role is not None:
        meta["role"] = role.strip() or DEFAULT_VERSION_ROLE
    meta["updated_at"] = _now_iso()
    _write_version_meta(path, meta)
    return _version_summary(key.source, key.owner, key.repo, path)


def delete_version(source: str, owner: str, repo: str, version: str) -> dict[str, Any]:
    key = parse_project_key(source, owner, repo)
    version_name = normalize_segment(version, field="version")
    path = version_dir(key.source, key.owner, key.repo, version_name)
    if not path.is_dir():
        raise FileNotFoundError(f"version does not exist: {version_name}")

    project_path = f"{key.source}/{key.owner}/{key.repo}/{version_name}"
    _assert_no_running_scans(project_path)
    _assert_no_running_imports(project_path)

    meta = _read_version_meta(path, key.source, key.owner, key.repo, version_name)
    mirror = _git_mirror_dir(key.source, key.owner, key.repo)
    if (path / ".git").exists() and mirror.exists():
        import subprocess

        subprocess.run(
            ["git", f"--git-dir={mirror}", "worktree", "remove", "--force", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    if path.exists():
        shutil.rmtree(path)
    return meta


def list_specific_runs(project_path: str) -> list[dict[str, Any]]:
    try:
        root = specific_root(project_path)
    except (FileNotFoundError, ValueError):
        return []

    if not root.is_dir():
        return []

    runs: list[dict[str, Any]] = []
    for run_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        meta = _read_json(run_dir / "run_meta.json") or {}
        artifacts = _list_known_artifacts(run_dir)
        runs.append(
            {
                "run_id": run_dir.name,
                "target_rel_dir": meta.get("target_rel_dir"),
                "created_at": meta.get("created_at"),
                "mode": meta.get("mode", "specific"),
                "artifacts": artifacts,
            }
        )
    runs.sort(key=lambda r: r["run_id"], reverse=True)
    return runs


KNOWN_ARTIFACTS = (
    "tree.json",
    "treescan_agent.json",
    "callscan_agent.json",
    "callscan_chains.jsonl",
    "callscan_chains.priority.jsonl",
    "callscan_chains.md",
    "audit_agent.json",
    "audit_findings.md",
    "run_meta.json",
)


def project_summary(project_path: str) -> dict[str, Any]:
    key = parse_project_path(project_path)
    proj = project_dir(project_path)
    base = proj / ARTIFACTS_DIRNAME
    version_meta = _read_version_meta(proj, key.source, key.owner, key.repo, key.version)
    return {
        "project_path": project_path,
        "project_root": str(proj),
        "version": version_meta,
        "has_artifacts": base.is_dir(),
        "artifacts": _list_known_artifacts(base) if base.is_dir() else {},
    }


def read_source_file(project_path: str, rel_path: str) -> dict[str, Any]:
    root = project_dir(project_path).resolve()
    clean = rel_path.replace("\\", "/").lstrip("/")
    target = (root / clean).resolve()
    try:
        target.relative_to(root)
    except ValueError as err:
        raise ValueError("非法的源码文件路径") from err
    if not target.is_file():
        raise FileNotFoundError(f"源码文件不存在：{clean}")

    stat = target.stat()
    max_bytes = 2 * 1024 * 1024
    with target.open("rb") as fp:
        raw = fp.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]
    try:
        content = raw.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content = raw.decode("utf-8", errors="replace")
        encoding = "utf-8-replace"
    return {
        "project_path": project_path,
        "path": str(target),
        "rel_path": clean,
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "encoding": encoding,
        "truncated": truncated,
        "content": content,
    }


def _project_summary_from_dir(
    source: str,
    owner: str,
    repo: str,
    repo_dir: Path,
    *,
    include_scan_summaries: bool = True,
) -> dict[str, Any]:
    meta = _read_project_meta(source, owner, repo)
    versions: list[dict[str, Any]] = []
    for version_path in sorted(p for p in repo_dir.iterdir() if p.is_dir()):
        if version_path.name.startswith(".") or version_path.name in RESERVED_PROJECT_CHILDREN:
            continue
        versions.append(
            _version_summary(
                source,
                owner,
                repo,
                version_path,
                include_scan_summaries=include_scan_summaries,
            )
        )

    scan_count = sum(int(v.get("scan_count") or 0) for v in versions)
    return {
        "project_key": f"{source}/{owner}/{repo}",
        "project_path": f"{source}/{owner}/{repo}",
        "source": source,
        "owner": owner,
        "repo": repo,
        "name": meta.get("name") or repo,
        "notes": meta.get("notes") or "",
        "description": meta.get("description") or "",
        "tags": _string_list(meta.get("tags")),
        "audit_status": meta.get("audit_status") or "not_started",
        "favorite": bool(meta.get("favorite")),
        "project_profile": _normalize_project_profile(meta.get("project_profile") or {}),
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
        "project_root": str(repo_dir),
        "versions": versions,
        "version_count": len(versions),
        "scan_count": scan_count,
    }


def _version_summary(
    source: str,
    owner: str,
    repo: str,
    version_path: Path,
    *,
    include_scan_summaries: bool = True,
) -> dict[str, Any]:
    version = version_path.name
    project_path = f"{source}/{owner}/{repo}/{version}"
    meta = _read_version_meta(version_path, source, owner, repo, version)
    scans: list[dict[str, Any]] = []
    latest_scan: dict[str, Any] | None = None
    if include_scan_summaries:
        scans = _safe_list_scans(project_path)
        latest_scan = scans[0] if scans else None
    else:
        scan_count = _count_scan_dirs(version_path)
    return {
        "project_path": project_path,
        "source": source,
        "owner": owner,
        "repo": repo,
        "version": version,
        "name": meta.get("name") or version,
        "notes": meta.get("notes") or "",
        "role": meta.get("role") or DEFAULT_VERSION_ROLE,
        "kind": meta.get("kind") or "manual",
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
        "project_root": str(version_path),
        "has_artifacts": (version_path / ARTIFACTS_DIRNAME).is_dir(),
        "scan_count": len(scans) if include_scan_summaries else scan_count,
        "latest_scan": latest_scan,
        "audit_summary": (latest_scan or {}).get("audit_summary") if latest_scan else None,
        "callscan_summary": (latest_scan or {}).get("callscan_summary") if latest_scan else None,
        "git": meta.get("git"),
    }


def _count_scan_dirs(version_path: Path) -> int:
    """仅统计 scans 目录数量，不读产物摘要。"""
    scans_root = version_path / ARTIFACTS_DIRNAME / "scans"
    if not scans_root.is_dir():
        return 0
    return sum(1 for p in scans_root.iterdir() if p.is_dir() and not p.name.startswith("."))


def _safe_list_scans(project_path: str) -> list[dict[str, Any]]:
    try:
        from app.server import scans as scans_mod

        return scans_mod.list_scans(project_path)
    except Exception:
        return []


def _project_meta_defaults(source: str, owner: str, repo: str) -> dict[str, Any]:
    now = _now_iso()
    return {
        "source": source,
        "owner": owner,
        "repo": repo,
        "project_key": f"{source}/{owner}/{repo}",
        "name": repo,
        "notes": "",
        "description": "",
        "tags": [],
        "audit_status": "not_started",
        "favorite": False,
        "project_profile": {},
        "created_at": now,
        "updated_at": now,
    }


def _version_meta_defaults(
    source: str,
    owner: str,
    repo: str,
    version: str,
    *,
    kind: str,
    name: str = "",
    notes: str = "",
    role: str = DEFAULT_VERSION_ROLE,
) -> dict[str, Any]:
    now = _now_iso()
    return {
        "source": source,
        "owner": owner,
        "repo": repo,
        "version": version,
        "project_path": f"{source}/{owner}/{repo}/{version}",
        "kind": kind,
        "role": role or DEFAULT_VERSION_ROLE,
        "name": name.strip() or version,
        "notes": notes,
        "created_at": now,
        "updated_at": now,
    }


def _ensure_project_container(source: str, owner: str, repo: str) -> Path:
    container = project_container_dir(source, owner, repo)
    container.mkdir(parents=True, exist_ok=True)
    _ensure_project_metadata(source, owner, repo)
    return container


def _ensure_project_metadata(source: str, owner: str, repo: str) -> dict[str, Any]:
    path = project_metadata_path(source, owner, repo)
    meta = _read_json(path)
    if meta:
        return meta
    meta = _project_meta_defaults(source, owner, repo)
    _write_json(path, meta)
    return meta


def _read_project_meta(source: str, owner: str, repo: str) -> dict[str, Any]:
    meta = _read_json(project_metadata_path(source, owner, repo))
    if not meta:
        meta = _project_meta_defaults(source, owner, repo)
    return meta


def _read_version_meta(
    version_path: Path,
    source: str,
    owner: str,
    repo: str,
    version: str,
) -> dict[str, Any]:
    meta = _read_json(version_path / ARTIFACTS_DIRNAME / VERSION_META_FILENAME)
    if not meta:
        meta = _version_meta_defaults(
            source,
            owner,
            repo,
            version,
            kind="manual",
            name=version,
        )
    return meta


def _write_version_meta(version_path: Path, meta: dict[str, Any]) -> None:
    meta["updated_at"] = _now_iso()
    _write_json(version_path / ARTIFACTS_DIRNAME / VERSION_META_FILENAME, meta)


def _prepare_version_target(target: Path, *, overwrite: bool) -> None:
    if not target.exists():
        return
    if not overwrite:
        raise FileExistsError(f"version already exists: {target.name}")
    project_path = _project_path_for_existing_version(target)
    if project_path:
        _assert_no_running_scans(project_path)
        _assert_no_running_imports(project_path)
    shutil.rmtree(target)


def _project_path_for_existing_version(target: Path) -> str | None:
    try:
        rel = target.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return None
    parts = rel.parts
    if len(parts) == 4:
        return "/".join(parts)
    return None


def _assert_no_running_scans(project_path: str) -> None:
    try:
        from app.server import scans as scans_mod

        for scan in scans_mod.list_scans(project_path):
            if scan.get("status") == "running":
                raise ValueError("cannot modify a version with a running scan")
    except FileNotFoundError:
        return


def _assert_no_running_imports(project_path: str) -> None:
    try:
        from app.server import import_jobs

        if import_jobs.has_running_job(project_path):
            raise ValueError("cannot modify a version with a running import job")
    except ImportError:
        return


def _copy_code_tree(src: Path, target: Path) -> None:
    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {name for name in names if name in {".defectmine", ".git"}}

    shutil.copytree(src, target, ignore=ignore)


def _git_mirror_dir(source: str, owner: str, repo: str) -> Path:
    return project_container_dir(source, owner, repo) / PROJECT_META_DIRNAME / "git" / "mirror.git"


def _list_known_artifacts(directory: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name in KNOWN_ARTIFACTS:
        p = directory / name
        if p.is_file():
            stat = p.stat()
            out[name] = {"size": stat.st_size, "mtime": stat.st_mtime}
    return out


def _read_json(path: Path) -> dict[str, Any] | None:
    return json_io.read_json_object(path)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    json_io.write_json(path, data, indent=True)


def _string_list(raw: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in raw or []:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _normalize_project_profile(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    blocked = {"project_name", "confidence", "limits"}
    return {str(k): v for k, v in raw.items() if k not in blocked}


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")

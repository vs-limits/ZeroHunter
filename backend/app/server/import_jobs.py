"""Background jobs for creating project versions from Git repositories."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

from app.server.paths import (
    ARTIFACTS_DIRNAME,
    PROJECT_META_DIRNAME,
    PROJECT_ROOT_DIR,
    VERSION_META_FILENAME,
    normalize_segment,
    parse_project_key,
    project_container_dir,
    version_dir,
)
from app.server.projects import _assert_no_running_scans, _ensure_project_metadata, _now_iso, _version_meta_defaults


TERMINAL_STATES = {"done", "error", "killed"}
_JOBS_LOCK = threading.Lock()
_JOBS: dict[str, "ImportJob"] = {}


@dataclass
class ImportJob:
    job_id: str
    project_key: str
    requested_project_path: str | None
    payload: dict[str, Any]
    status: str = "pending"
    return_code: int | None = None
    started_at: float | None = None
    finished_at: float | None = None
    lines: list[str] = field(default_factory=list)
    error: str | None = None
    version: str | None = None
    project_path: str | None = None
    git: dict[str, Any] | None = None
    process: subprocess.Popen | None = None
    listeners: list[asyncio.Queue] = field(default_factory=list)
    loop: asyncio.AbstractEventLoop | None = None

    def to_dict(self, *, include_lines: bool = True) -> dict[str, Any]:
        data = {
            "job_id": self.job_id,
            "project_key": self.project_key,
            "requested_project_path": self.requested_project_path,
            "status": self.status,
            "return_code": self.return_code,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "version": self.version,
            "project_path": self.project_path,
            "git": self.git,
        }
        if include_lines:
            data["lines"] = list(self.lines)
        return data


def start_git_import(
    source: str,
    owner: str,
    repo: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    key = parse_project_key(source, owner, repo)
    clean_payload = dict(payload)
    clean_payload.update({"source": key.source, "owner": key.owner, "repo": key.repo})
    version = str(clean_payload.get("version") or "").strip()
    requested_project_path = (
        f"{key.source}/{key.owner}/{key.repo}/{version}" if version else None
    )
    job = ImportJob(
        job_id=uuid.uuid4().hex[:12],
        project_key=key.project_key,
        requested_project_path=requested_project_path,
        payload=clean_payload,
    )
    try:
        job.loop = asyncio.get_event_loop()
    except RuntimeError:
        job.loop = None

    with _JOBS_LOCK:
        _JOBS[job.job_id] = job

    threading.Thread(target=_run_git_import_job, args=(job,), daemon=True).start()
    return job.to_dict()


def get_job(job_id: str) -> dict[str, Any] | None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    return job.to_dict() if job else None


def retry_job(job_id: str) -> dict[str, Any]:
    with _JOBS_LOCK:
        old = _JOBS.get(job_id)
    if not old:
        raise FileNotFoundError(f"import job not found: {job_id}")
    if old.status not in TERMINAL_STATES:
        raise ValueError("only finished jobs can be retried")
    payload = dict(old.payload)
    return start_git_import(payload["source"], payload["owner"], payload["repo"], payload)


def stop_job(job_id: str) -> bool:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if not job or job.status not in {"pending", "running"}:
        return False
    job.status = "killed"
    proc = job.process
    if proc is not None:
        try:
            proc.terminate()
        except OSError:
            return False
    _broadcast(job, {"type": "status", "status": job.status})
    return True


def has_running_job(project_path: str) -> bool:
    with _JOBS_LOCK:
        jobs = list(_JOBS.values())
    for job in jobs:
        if job.status not in {"pending", "running"}:
            continue
        if job.project_path == project_path or job.requested_project_path == project_path:
            return True
    return False


def list_git_refs(
    source: str,
    owner: str,
    repo: str,
    *,
    git_url: str = "",
    refresh: bool = False,
) -> dict[str, Any]:
    """List selectable branches and tags before or after a mirror import."""
    key = parse_project_key(source, owner, repo)
    remote = str(git_url or "").strip()
    container = project_container_dir(key.source, key.owner, key.repo)
    mirror = container / PROJECT_META_DIRNAME / "git" / "mirror.git"

    if remote:
        refs_text = _run_git_ref_command(
            ["git", "ls-remote", "--heads", "--tags", remote],
            cwd=PROJECT_ROOT_DIR,
        )
        source_kind = "remote"
    elif _git_mirror_usable(mirror):
        if refresh:
            _run_git_ref_command(
                ["git", f"--git-dir={mirror}", "fetch", "--all", "--tags", "--prune"],
                cwd=container,
            )
        remote = _run_git_ref_command(
            ["git", f"--git-dir={mirror}", "config", "--get", "remote.origin.url"],
            cwd=container,
            allow_error=True,
        ).strip()
        refs_text = _run_git_ref_command(
            ["git", f"--git-dir={mirror}", "show-ref", "--dereference", "--heads", "--tags"],
            cwd=container,
        )
        source_kind = "mirror"
    else:
        raise ValueError("git_url is required before the first Git import")

    items = _parse_git_refs(refs_text)
    branches = sum(1 for item in items if item["kind"] == "branch")
    tags = sum(1 for item in items if item["kind"] == "tag")
    return {
        "project_key": key.project_key,
        "remote": remote,
        "source": source_kind,
        "count": len(items),
        "branches": branches,
        "tags": tags,
        "items": items,
    }


async def stream_job(job_id: str) -> AsyncIterator[str]:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        yield _sse({"type": "error", "message": f"import job not found: {job_id}"})
        return

    queue: asyncio.Queue = asyncio.Queue()
    job.listeners.append(queue)
    for line in list(job.lines):
        yield _sse({"type": "stdout", "line": line})

    if job.status in TERMINAL_STATES:
        yield _sse({"type": "status", **job.to_dict(include_lines=False)})
        yield _sse({"type": "end"})
        return

    try:
        while True:
            item = await queue.get()
            if item is None:
                yield _sse({"type": "status", **job.to_dict(include_lines=False)})
                yield _sse({"type": "end"})
                return
            yield _sse(item)
    finally:
        try:
            job.listeners.remove(queue)
        except ValueError:
            pass


def _run_git_import_job(job: ImportJob) -> None:
    job.status = "running"
    job.started_at = time.time()
    _broadcast(job, {"type": "status", "status": job.status})
    try:
        _perform_git_import(job)
        if job.status != "killed":
            job.status = "done"
            job.return_code = 0
    except Exception as err:
        if job.status != "killed":
            job.status = "error"
            job.error = str(err)
            _append_line(job, f"[error] {err}")
    finally:
        job.finished_at = time.time()
        _broadcast(job, None)


def _perform_git_import(job: ImportJob) -> None:
    payload = job.payload
    source = payload["source"]
    owner = payload["owner"]
    repo = payload["repo"]
    git_url = str(payload.get("git_url") or "").strip()
    if not git_url:
        raise ValueError("git_url is required")

    ref = str(payload.get("ref") or "HEAD").strip() or "HEAD"
    overwrite = bool(payload.get("overwrite"))
    depth = _optional_positive_int(payload.get("depth"))
    single_branch = bool(payload.get("single_branch"))
    recurse_submodules = bool(payload.get("recurse_submodules"))
    role = str(payload.get("role") or "baseline")
    notes = str(payload.get("notes") or "")
    display_name = str(payload.get("name") or "")

    container = project_container_dir(source, owner, repo)
    container.mkdir(parents=True, exist_ok=True)
    _ensure_project_metadata(source, owner, repo)

    mirror = container / PROJECT_META_DIRNAME / "git" / "mirror.git"
    mirror.parent.mkdir(parents=True, exist_ok=True)
    if mirror.is_dir() and not _git_mirror_usable(mirror):
        _append_line(
            job,
            f"[warn] mirror exists but is not a valid git repo ({mirror}); "
            "removing and re-cloning (likely interrupted by a previous import)",
        )
        shutil.rmtree(mirror, ignore_errors=True)

    if not _git_mirror_usable(mirror):
        cmd = ["git", "clone", "--mirror", "--progress"]
        if depth:
            cmd.append(f"--depth={depth}")
        if single_branch and ref != "HEAD":
            cmd += ["--branch", ref, "--single-branch"]
        cmd += [git_url, str(mirror)]
        _run(job, cmd, cwd=str(container))
    else:
        cmd = ["git", "--git-dir", str(mirror), "fetch", "--all", "--tags", "--prune", "--progress"]
        if depth:
            cmd.append(f"--depth={depth}")
        _run(job, cmd, cwd=str(container))

    commit = _capture(job, ["git", f"--git-dir={mirror}", "rev-parse", f"{ref}^{{commit}}"], cwd=container)
    short = _capture(job, ["git", f"--git-dir={mirror}", "rev-parse", "--short=12", commit], cwd=container)
    describe = _capture(
        job,
        ["git", f"--git-dir={mirror}", "describe", "--tags", "--always", "--abbrev=12", commit],
        cwd=container,
        allow_error=True,
    ) or short
    branch_or_ref = _ref_label(job, mirror, ref)
    version = str(payload.get("version") or "").strip()
    if version:
        version_name = normalize_segment(version, field="version")
    else:
        version_name = normalize_segment(f"{_slug(branch_or_ref)}__{short}", field="version")

    target = version_dir(source, owner, repo, version_name)
    project_path = f"{source}/{owner}/{repo}/{version_name}"
    _assert_no_running_scans(project_path)
    if target.exists():
        if not overwrite:
            raise FileExistsError(f"version already exists: {version_name}")
        shutil.rmtree(target)

    _run(
        job,
        ["git", f"--git-dir={mirror}", "worktree", "add", "--detach", str(target), commit],
        cwd=str(container),
    )
    if recurse_submodules:
        _run(job, ["git", "-C", str(target), "submodule", "update", "--init", "--recursive"], cwd=str(target))

    git_meta = {
        "remote": git_url,
        "ref": ref,
        "commit": commit,
        "short_commit": short,
        "describe": describe,
        "worktree": True,
    }
    meta = _version_meta_defaults(
        source,
        owner,
        repo,
        version_name,
        kind="git",
        name=display_name,
        notes=notes,
        role=role,
    )
    meta["git"] = git_meta
    meta["updated_at"] = _now_iso()
    meta_path = target / ARTIFACTS_DIRNAME / VERSION_META_FILENAME
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    job.version = version_name
    job.project_path = project_path
    job.git = git_meta
    _append_line(job, f"[done] created version {project_path}")


def _run(job: ImportJob, cmd: list[str], *, cwd: str | Path) -> None:
    _append_line(job, f"$ {_quote_cmd(cmd)}")
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=env,
    )
    job.process = proc
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            if job.status == "killed":
                break
            _append_line(job, raw.rstrip("\r\n"))
    finally:
        proc.stdout.close()
    rc = proc.wait()
    job.process = None
    if job.status == "killed":
        raise RuntimeError("job killed")
    if rc != 0:
        raise RuntimeError(f"command failed with exit code {rc}: {_quote_cmd(cmd)}")


def _capture(
    job: ImportJob,
    cmd: list[str],
    *,
    cwd: str | Path,
    allow_error: bool = False,
) -> str:
    _append_line(job, f"$ {_quote_cmd(cmd)}")
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    out = proc.stdout.strip()
    if out:
        for line in out.splitlines():
            _append_line(job, line)
    if proc.returncode != 0:
        if allow_error:
            return ""
        raise RuntimeError(f"command failed with exit code {proc.returncode}: {_quote_cmd(cmd)}")
    return out.splitlines()[-1].strip() if out else ""


def _ref_label(job: ImportJob, mirror: Path, ref: str) -> str:
    if ref != "HEAD":
        return ref
    head = _capture(
        job,
        ["git", f"--git-dir={mirror}", "symbolic-ref", "--short", "HEAD"],
        cwd=mirror.parent,
        allow_error=True,
    )
    return head or "HEAD"


def _git_mirror_usable(mirror: Path) -> bool:
    """True only when ``mirror`` is a complete bare repository (not a half-written clone)."""
    if not mirror.is_dir():
        return False
    probe = subprocess.run(
        ["git", "--git-dir", str(mirror), "rev-parse", "--git-dir"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return probe.returncode == 0


def _optional_positive_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _slug(value: str) -> str:
    text = re.sub(r"[^0-9A-Za-z._-]+", "-", value.strip() or "ref")
    text = text.strip(".-_")
    return text or "ref"


def _quote_cmd(cmd: list[str]) -> str:
    return " ".join(_quote_part(part) for part in cmd)


def _quote_part(part: str) -> str:
    if re.search(r"\s", part):
        return json.dumps(part)
    return part


def _run_git_ref_command(
    cmd: list[str],
    *,
    cwd: str | Path,
    allow_error: bool = False,
) -> str:
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=60,
            env=env,
        )
    except subprocess.TimeoutExpired as err:
        raise ValueError("git ref query timed out") from err
    out = proc.stdout or ""
    if proc.returncode != 0 and not allow_error:
        tail = "\n".join(out.strip().splitlines()[-5:])
        detail = f": {tail}" if tail else ""
        raise ValueError(f"git ref query failed with exit code {proc.returncode}{detail}")
    return out


def _parse_git_refs(output: str) -> list[dict[str, Any]]:
    by_full_ref: dict[str, dict[str, Any]] = {}
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("ref:"):
            continue

        parts = re.split(r"\s+", line, maxsplit=1)
        if len(parts) != 2:
            continue
        commit, full_ref = parts[0].strip(), parts[1].strip()
        if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            continue

        peeled = False
        if full_ref.endswith("^{}"):
            full_ref = full_ref[:-3]
            peeled = True

        kind: str
        name: str
        if full_ref.startswith("refs/heads/"):
            kind = "branch"
            name = full_ref.removeprefix("refs/heads/")
        elif full_ref.startswith("refs/tags/"):
            kind = "tag"
            name = full_ref.removeprefix("refs/tags/")
        else:
            continue

        existing = by_full_ref.get(full_ref)
        if existing is None:
            by_full_ref[full_ref] = {
                "kind": kind,
                "name": name,
                "ref": name,
                "full_ref": full_ref,
                "commit": commit,
                "short_commit": commit[:12],
                "peeled": peeled,
            }
        elif peeled:
            existing["commit"] = commit
            existing["short_commit"] = commit[:12]
            existing["peeled"] = True

    return sorted(
        by_full_ref.values(),
        key=lambda item: (0 if item["kind"] == "branch" else 1, item["name"].lower()),
    )


def _append_line(job: ImportJob, line: str) -> None:
    job.lines.append(line)
    _broadcast(job, {"type": "stdout", "line": line})


def _broadcast(job: ImportJob, item: dict[str, Any] | None) -> None:
    loop = job.loop
    for queue in list(job.listeners):
        if loop is not None:
            loop.call_soon_threadsafe(queue.put_nowait, item)
        else:
            try:
                queue.put_nowait(item)
            except Exception:
                pass


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

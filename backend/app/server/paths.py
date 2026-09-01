"""Repository, project-version and artifact path helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT_DIR = Path(__file__).resolve().parents[3]
REPO_ROOT = PROJECT_ROOT_DIR / "repo"
ARTIFACTS_DIRNAME = ".defectmine"
PROJECT_META_DIRNAME = ".defectmine_repo"
PROJECT_META_FILENAME = "project.json"
VERSION_META_FILENAME = "version.json"
SCANS_DIRNAME = "scans"
SPECIFIC_DIRNAME = "specific"
LEGACY_ROOT_ID = "legacy-root"
LEGACY_PREFIX = "legacy-"


@dataclass(frozen=True)
class ProjectKey:
    source: str
    owner: str
    repo: str

    @property
    def project_key(self) -> str:
        return f"{self.source}/{self.owner}/{self.repo}"


@dataclass(frozen=True)
class VersionKey(ProjectKey):
    version: str

    @property
    def project_path(self) -> str:
        return f"{self.source}/{self.owner}/{self.repo}/{self.version}"


def repo_root() -> Path:
    return REPO_ROOT


def normalize_segment(value: str, *, field: str = "path segment") -> str:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        raise ValueError(f"{field} cannot be empty")
    if "/" in text or text in {".", ".."}:
        raise ValueError(f"{field} cannot contain path separators or dot segments")
    return text


def parse_project_key(source: str, owner: str, repo: str) -> ProjectKey:
    return ProjectKey(
        normalize_segment(source, field="source"),
        normalize_segment(owner, field="owner"),
        normalize_segment(repo, field="repo"),
    )


def parse_project_path(project_path: str) -> VersionKey:
    """Parse ``source/owner/repo/version`` and reject legacy three-part paths."""
    text = (project_path or "").replace("\\", "/").strip("/")
    if not text:
        raise ValueError("project_path cannot be empty")
    parts = [p for p in text.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        raise ValueError("project_path cannot contain ..")
    if len(parts) != 4:
        raise ValueError(
            "project_path must be source/owner/repo/version; legacy three-part paths are not supported"
        )
    source, owner, repo, version = parts
    return VersionKey(
        normalize_segment(source, field="source"),
        normalize_segment(owner, field="owner"),
        normalize_segment(repo, field="repo"),
        normalize_segment(version, field="version"),
    )


def project_container_dir(source: str, owner: str, repo: str) -> Path:
    key = parse_project_key(source, owner, repo)
    full = (REPO_ROOT / key.source / key.owner / key.repo).resolve()
    _assert_under_repo(full)
    return full


def project_dir(project_path: str) -> Path:
    """Return the absolute version directory for ``source/owner/repo/version``."""
    key = parse_project_path(project_path)
    full = (REPO_ROOT / key.source / key.owner / key.repo / key.version).resolve()
    _assert_under_repo(full)
    if not full.is_dir():
        raise FileNotFoundError(f"project version directory does not exist: {full}")
    return full


def version_dir(source: str, owner: str, repo: str, version: str) -> Path:
    key = parse_project_key(source, owner, repo)
    version_name = normalize_segment(version, field="version")
    full = (REPO_ROOT / key.source / key.owner / key.repo / version_name).resolve()
    _assert_under_repo(full)
    return full


def project_metadata_dir(source: str, owner: str, repo: str) -> Path:
    return project_container_dir(source, owner, repo) / PROJECT_META_DIRNAME


def project_metadata_path(source: str, owner: str, repo: str) -> Path:
    return project_metadata_dir(source, owner, repo) / PROJECT_META_FILENAME


def version_metadata_path(project_path: str) -> Path:
    return project_dir(project_path) / ARTIFACTS_DIRNAME / VERSION_META_FILENAME


def artifacts_dir(project_path: str, run_id: str | None = None) -> Path:
    """Resolve the artifact directory for a version-level project path."""
    proj = project_dir(project_path)
    base = proj / ARTIFACTS_DIRNAME

    if not run_id:
        return base

    if run_id == LEGACY_ROOT_ID:
        return base

    if run_id.startswith(LEGACY_PREFIX):
        legacy_id = run_id[len(LEGACY_PREFIX):]
        path = base / SPECIFIC_DIRNAME / legacy_id
        if not path.is_dir():
            raise FileNotFoundError(f"legacy scan directory does not exist: {path}")
        return path

    scan_path = base / SCANS_DIRNAME / run_id
    if scan_path.is_dir():
        return scan_path

    legacy_path = base / SPECIFIC_DIRNAME / run_id
    if legacy_path.is_dir():
        return legacy_path

    raise FileNotFoundError(f"scan directory does not exist: {scan_path}")


def specific_root(project_path: str) -> Path:
    return project_dir(project_path) / ARTIFACTS_DIRNAME / SPECIFIC_DIRNAME


def _assert_under_repo(path: Path) -> None:
    repo_resolved = REPO_ROOT.resolve()
    try:
        path.relative_to(repo_resolved)
    except ValueError as err:
        raise ValueError("path must stay under repo/") from err

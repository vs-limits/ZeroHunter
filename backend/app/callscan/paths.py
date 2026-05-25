from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


ARTIFACTS_DIRNAME = ".defectmine"


class PathPolicyError(ValueError):
    """Raised when an input path cannot be safely normalized under repo root."""


#----------- CallScan 路径上下文：统一保存仓库根目录和 .defectmine 产物目录 ------------#
@dataclass(frozen=True, slots=True)
class RepoPathContext:
    root: Path
    artifacts_dir: Path

    @classmethod
    def from_project(
        cls,
        project_path: str | Path,
        *,
        artifacts_dir: str | Path | None = None,
    ) -> "RepoPathContext":
        root = resolve_repo_root(project_path)
        return cls(
            root=root,
            artifacts_dir=resolve_artifacts_dir(root, artifacts_dir),
        )

    def artifact_path(self, filename: str) -> Path:
        return self.artifacts_dir / filename

    def normalize(self, path: str | Path) -> dict[str, Any]:
        return normalize_repo_path(self.root, path)

    def relative(self, path: str | Path) -> str:
        return to_repo_relative(self.root, path)

    def absolute(self, path: str | Path) -> Path:
        return to_repo_absolute(self.root, path)


def resolve_repo_root(project_path: str | Path) -> Path:
    root = Path(project_path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Project root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Project root is not a directory: {root}")
    return root


def resolve_artifacts_dir(root: Path, artifacts_dir: str | Path | None = None) -> Path:
    if artifacts_dir is None:
        return (root / ARTIFACTS_DIRNAME).resolve()

    path = Path(artifacts_dir).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve()


#----------- 路径规范化：所有跨工具路径都转成 repo 相对 POSIX 路径，避免 Windows 分隔符污染证据 ------------#
def normalize_repo_path(root: Path, path: str | Path) -> dict[str, Any]:
    absolute_path = to_repo_absolute(root, path)
    relative_path = to_repo_relative(root, absolute_path)
    return {
        "absolute_path": str(absolute_path),
        "relative_path": relative_path,
        "path": relative_path,
        "is_artifact": is_artifact_path(relative_path),
    }


def to_repo_absolute(root: Path, path: str | Path) -> Path:
    root = root.resolve()
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate

    resolved = candidate.resolve()
    _assert_inside_root(root, resolved)
    return resolved


def to_repo_relative(root: Path, path: str | Path) -> str:
    root = root.resolve()
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate

    resolved = candidate.resolve()
    _assert_inside_root(root, resolved)
    relative = resolved.relative_to(root).as_posix()
    return "." if relative == "" else relative


def is_artifact_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/").lstrip("./")
    return normalized == ARTIFACTS_DIRNAME or normalized.startswith(f"{ARTIFACTS_DIRNAME}/")


def _assert_inside_root(root: Path, path: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise PathPolicyError(f"Path escapes project root: {path}") from exc

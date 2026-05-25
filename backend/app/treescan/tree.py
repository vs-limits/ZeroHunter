from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from app.agent import AgentType, run_agent
from app.callscan.rules import DIR_DENY, FILE_DENY


ARTIFACTS_DIRNAME = ".defectmine"
TREE_FILENAME = "tree.json"
TREESCAN_PROFILE_FILENAME = "treescan_agent.json"
TREESCAN_RAW_PROFILE_FILENAME = "treescan_agent.raw.txt"
ProgressReporter = Callable[[dict[str, Any]], None]

MAX_FILES = 20000
MAX_DEPTH = 18
MAX_TOTAL_SIZE = 500 * 1024 * 1024

DEFAULT_EXCLUDED_DIRS = DIR_DENY
DEFAULT_EXCLUDED_FILES = FILE_DENY

LANGUAGE_RULES = {
    "php": {"suffixes": {".php"}},
    "javascript": {"suffixes": {".js", ".mjs", ".cjs", ".jsx"}},
    "typescript": {"suffixes": {".ts", ".tsx"}},
    "python": {"suffixes": {".py"}},
    "java": {"suffixes": {".java"}},
    "go": {"suffixes": {".go"}},
    "rust": {"suffixes": {".rs"}},
    "ruby": {"suffixes": {".rb"}},
    "csharp": {"suffixes": {".cs"}},
    "cpp": {"suffixes": {".cpp", ".c", ".h"}},
    "twig": {"suffixes": {".twig"}},
    "html": {"suffixes": {".html"}},
    "css": {"suffixes": {".css", ".scss"}},
    "sql": {"suffixes": {".sql"}},
    "yaml": {"suffixes": {".yaml", ".yml"}},
    "json": {"suffixes": {".json"}},
    "xml": {"suffixes": {".xml"}},
}

LANGUAGE_BY_SUFFIX = {
    suffix: language
    for language, rule in LANGUAGE_RULES.items()
    for suffix in rule["suffixes"]
}

MANIFEST_FILES = {
    "composer.json": "php-composer",
    "package.json": "node",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "Gemfile": "ruby",
}

CONFIG_FILE_NAMES = {
    ".env",
    ".env.example",
    ".htaccess",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    "Makefile",
    "composer.json",
    "composer.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "services.yaml",
    "config.yaml",
    "config.yml",
    "phpunit.xml",
    "playwright.config.ts",
}

DOCUMENTATION_NAMES = {
    "README",
    "README.md",
    "INSTALL.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
}

FOCUS_RULES = {
    "entrypoint": {
        "dir_keywords": {"routes", "router", "controllers", "controller", "handlers", "handler", "actions", "api", "gateway"},
        "file_keywords": {"index", "main", "server", "app", "bootstrap", "wakka"},
        "priority": "high",
    },
    "auth": {
        "dir_keywords": {"auth", "acl", "acls", "permission", "permissions", "user", "users", "login", "session"},
        "file_keywords": {"auth", "login", "user", "acl", "csrf", "token", "password", "session"},
        "priority": "high",
    },
    "database": {
        "dir_keywords": {"db", "database", "repository", "repositories", "migration", "migrations", "models", "entities"},
        "file_keywords": {"db", "database", "migration", "sql", "query"},
        "priority": "high",
    },
    "file-io": {
        "dir_keywords": {"upload", "uploads", "files", "file", "backup", "backups", "archive", "archives", "import", "export"},
        "file_keywords": {"upload", "uploads", "backup", "archive", "import", "export", "download"},
        "priority": "high",
    },
    "template": {
        "dir_keywords": {"template", "templates", "views", "view", "twig", "theme", "themes", "formatter", "formatters"},
        "file_keywords": {"template", "render", "view", "twig", "formatter"},
        "priority": "medium",
    },
    "command": {
        "dir_keywords": {"command", "commands", "cli", "console", "script", "scripts", "worker", "workers", "scheduler"},
        "file_keywords": {"command", "console", "cli", "exec", "shell"},
        "priority": "high",
    },
    "config": {
        "dir_keywords": {"config", "configuration", "setup", "install", "docker"},
        "file_keywords": {"config", "configuration", "setup", "install", "docker"},
        "priority": "medium",
    },
    "integration": {
        "dir_keywords": {"http", "client", "clients", "webhook", "webhooks", "mailer", "mail", "api"},
        "file_keywords": {"http", "curl", "client", "mail", "webhook", "api"},
        "priority": "medium",
    },
    "test": {
        "dir_keywords": {"test", "tests", "spec", "specs"},
        "file_keywords": {"test", "spec"},
        "priority": "low",
    },
}

DEFAULT_SCANNER_EXCLUDE_PATHS = [
    ".git/",
    ".defectmine/",
    "node_modules/",
    "vendor/",
    "dist/",
    "build/",
    "coverage/",
    "target/",
    ".venv/",
    "venv/",
    "__pycache__/",
]

SCANNER_PRIORITY_EXCLUDED_PREFIXES = (
    ".github/",
    "docs/",
    "doc/",
    "documentation/",
    "test/",
    "tests/",
    "spec/",
    "specs/",
)

LANGUAGE_ALIASES = {
    "php": "php",
    "twig": "php",
    "javascript": "javascript",
    "typescript": "javascript",
    "python": "python",
    "java": "java",
    "go": "go",
    "ruby": "ruby",
    "csharp": "csharp",
    "c#": "csharp",
}

SINK_CATEGORY_BY_ATTACK_SURFACE = {
    "upload": ["file-upload", "file-read-write"],
    "file-io": ["file-read-write"],
    "template-render": ["template-render"],
    "sql-access": ["sql-query"],
    "command-execution": ["command-execution"],
    "deserialization": ["deserialization"],
    "auth": ["auth"],
    "plugin-loading": ["plugin-loading"],
}

SOURCE_PATTERNS_BY_LANGUAGE = {
    "php": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "php://input"],
    "javascript": ["req.query", "req.body", "req.params", "location.search", "document.cookie"],
    "python": ["request.args", "request.form", "request.files", "request.json"],
    "java": ["getParameter", "getHeader", "getInputStream"],
    "go": ["r.URL.Query", "r.FormValue", "r.Header.Get"],
    "ruby": ["params", "request.params", "cookies"],
    "csharp": ["Request.Query", "Request.Form", "Request.Cookies", "Request.Headers"],
}

RG_INCLUDE_GLOBS_BY_LANGUAGE = {
    "php": ["*.php", "*.twig"],
    "javascript": ["*.js", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.jsx"],
    "python": ["*.py"],
    "java": ["*.java", "*.jsp"],
    "go": ["*.go"],
    "ruby": ["*.rb"],
    "csharp": ["*.cs", "*.cshtml"],
}


@dataclass(frozen=True, slots=True)
class ScanEntry:
    type: str
    name: str
    path: str
    suffix: str
    depth: int
    size: int = 0

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "path": self.path,
            "depth": self.depth,
        }
        if self.suffix:
            result["suffix"] = self.suffix
        if self.type == "file":
            result["size"] = self.size
        return result


@dataclass(slots=True)
class ScanState:
    root: Path
    budget: dict[str, Any] = field(default_factory=dict)
    total_files: int = 0
    total_dirs: int = 0
    total_size: int = 0
    extension_counts: Counter[str] = field(default_factory=Counter)
    top_level_dirs: set[str] = field(default_factory=set)
    top_level_files: set[str] = field(default_factory=set)
    manifest_files: list[dict[str, Any]] = field(default_factory=list)
    config_files: list[dict[str, Any]] = field(default_factory=list)
    documentation_files: list[dict[str, Any]] = field(default_factory=list)
    test_paths: list[dict[str, Any]] = field(default_factory=list)
    focus_items: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)
    dir_names: set[str] = field(default_factory=set)
    file_names: set[str] = field(default_factory=set)
    path_flags: set[str] = field(default_factory=set)
    hot_directory_counts: Counter[str] = field(default_factory=Counter)


@dataclass(frozen=True, slots=True)
class TreeScanResult:
    root: Path
    artifacts_dir: Path
    tree: dict[str, Any]
    profile: dict[str, Any]
    raw_profile: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "artifacts_dir": str(self.artifacts_dir),
            "tree": self.tree,
            "profile": self.profile,
            "raw_profile": self.raw_profile,
        }

    def state_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "artifacts_dir": str(self.artifacts_dir),
            "artifacts": {
                "tree": str(self.artifacts_dir / TREE_FILENAME),
                "profile": str(self.artifacts_dir / TREESCAN_PROFILE_FILENAME),
                "raw_profile": str(self.artifacts_dir / TREESCAN_RAW_PROFILE_FILENAME),
            },
            "summary": self.tree.get("summary", {}),
            "profile_summary": _profile_state_summary(self.profile),
        }


def run_treescan(
    project_path: str | Path,
    *,
    artifacts_dir: str | Path | None = None,
    persist: bool = True,
    progress_reporter: ProgressReporter | None = None,
) -> TreeScanResult:
    """
    Execute directory scanning and the TreeScan Agent as one stage.

    Workflow code should call this function instead of coordinating tree
    scanning and Agent invocation separately.
    """
    root = resolve_scan_root(project_path)
    output_dir = _resolve_artifacts_dir(root, artifacts_dir)

    if persist:
        output_dir.mkdir(parents=True, exist_ok=True)

    #----------- TreeScan 过程事件：通知 CLI 当前正在扫描哪个项目目录 ------------#
    _report_progress(
        progress_reporter,
        {
            "event": "treescan_scan_started",
            "root": str(root),
        },
    )

    tree = scan_project_tree(root)
    tree_summary = tree.get("summary", {})
    tree_json = json.dumps(tree, ensure_ascii=False, indent=2)
    tree_chars = len(tree_json)
    _report_progress(
        progress_reporter,
        {
            "event": "treescan_tree_ready",
            "root": str(root),
            "total_files": tree_summary.get("total_files", 0),
            "total_dirs": tree_summary.get("total_dirs", 0),
            "tree_chars": tree_chars,
        },
    )
    if persist:
        _write_json(tree, output_dir / TREE_FILENAME)
        _report_progress(
            progress_reporter,
            {
                "event": "treescan_tree_written",
                "path": str(output_dir / TREE_FILENAME),
            },
        )

    raw_profile, input_chars = _call_treescan_agent(tree)
    _report_progress(
        progress_reporter,
        {
            "event": "treescan_agent_submitted",
            "input_chars": input_chars,
        },
    )
    if persist:
        _write_text(raw_profile, output_dir / TREESCAN_RAW_PROFILE_FILENAME)
        _report_progress(
            progress_reporter,
            {
                "event": "treescan_raw_written",
                "path": str(output_dir / TREESCAN_RAW_PROFILE_FILENAME),
            },
        )

    profile = _enrich_profile_from_tree(_parse_treescan_profile(raw_profile), tree)
    if persist:
        _write_json(profile, output_dir / TREESCAN_PROFILE_FILENAME)
        _report_progress(
            progress_reporter,
            {
                "event": "treescan_profile_written",
                "path": str(output_dir / TREESCAN_PROFILE_FILENAME),
                "profile_summary": _profile_state_summary(profile),
            },
        )

    return TreeScanResult(
        root=root,
        artifacts_dir=output_dir,
        tree=tree,
        profile=profile,
        raw_profile=raw_profile,
    )


def run_treescan_agent(tree: dict[str, Any]) -> str:
    raw_profile, _ = _call_treescan_agent(tree)
    return raw_profile


#----------- TreeScan Agent 调用封装：统一复用精简后的画像输入与字符统计 ------------#
def _call_treescan_agent(tree: dict[str, Any]) -> tuple[str, int]:
    agent_input = _build_agent_input(tree)
    tree_json = json.dumps(agent_input, ensure_ascii=False, indent=2)
    return run_agent(AgentType.TREESCAN, tree_json), len(tree_json)


def resolve_scan_root(project_path: str | Path) -> Path:
    """Resolve and validate the project root used by the scan pipeline."""
    root = Path(project_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Scan root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Scan root is not a directory: {root}")

    return root


def scan_project_tree(
    project_path: str | Path,
    *,
    excluded_dirs: Iterable[str] | None = None,
    excluded_files: Iterable[str] | None = None,
) -> dict[str, Any]:
    """
    为 TreeScan 构建一个确定性、可进行 JSON 序列化的项目映射。该扫描过程会有意仅记录：路径、名称、文件后缀、、基于约定的元数据
    而不会记录源代码文件内容。这样可以使流水线的第一阶段保持轻量、低成本，同时为后续 Agent 提供更加密集、结构化的项目地图信息。
    """
    root = resolve_scan_root(project_path)
    ignored_dirs = DEFAULT_EXCLUDED_DIRS | set(excluded_dirs or ())
    ignored_files = DEFAULT_EXCLUDED_FILES | set(excluded_files or ())

    summary, metadata, signals, focus_paths, hot_directories = _stream_scan_project(
        root,
        ignored_dirs,
        ignored_files,
    )
    scan_plan = _build_scan_plan(focus_paths, signals)
    deterministic = _build_deterministic_profile(signals, focus_paths, hot_directories)

    return {
        "schema_version": "defectmine.tree.v2",
        "root": {
            "name": root.name,
            "path": ".",
            "absolute_path": str(root),
        },
        "summary": summary,
        "metadata": metadata,
        "signals": signals,
        "focus_paths": focus_paths,
        "scan_plan": scan_plan,
        "hot_directories": hot_directories,
        "deterministic": deterministic,
    }


def _stream_scan_project(
    root: Path,
    excluded_dirs: set[str],
    excluded_files: set[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, str]], list[dict[str, Any]]]:
    state = ScanState(root=root)
    state.budget = {
        "max_files": MAX_FILES,
        "max_depth": MAX_DEPTH,
        "max_total_size": MAX_TOTAL_SIZE,
        "truncated": False,
        "reason": "",
        "total_size": 0,
        "skipped_symlinks": 0,
    }
    stack: list[tuple[Path, int]] = [(root, 0)]
    root_resolved = root.resolve()
    _record_scan_entry(
        state,
        ScanEntry(type="directory", name=root.name, path=".", suffix="", depth=0),
    )

    while stack:
        current, depth = stack.pop()
        if depth >= MAX_DEPTH:
            _mark_budget_truncated(state, "max_depth")
            continue

        for child in _iter_scandir(current):
            name = child.name
            child_path = Path(child.path)

            if child.is_symlink():
                state.budget["skipped_symlinks"] += 1
                continue

            try:
                is_dir = child.is_dir(follow_symlinks=False)
                is_file = child.is_file(follow_symlinks=False)
            except OSError:
                continue

            if is_dir:
                if name in excluded_dirs:
                    continue
                if not _is_inside_root(child_path, root_resolved):
                    state.budget["skipped_symlinks"] += 1
                    continue
                relative_path = _relative_posix(child_path, root)
                _record_scan_entry(
                    state,
                    ScanEntry(
                        type="directory",
                        name=name,
                        path=relative_path,
                        suffix="",
                        depth=depth + 1,
                    )
                )
                stack.append((child_path, depth + 1))
                continue

            if not is_file or name in excluded_files:
                continue
            if state.total_files >= MAX_FILES:
                _mark_budget_truncated(state, "max_files")
                stack.clear()
                break

            try:
                stat = child.stat(follow_symlinks=False)
            except OSError:
                file_size = 0
            else:
                file_size = int(stat.st_size)

            if state.total_size + file_size > MAX_TOTAL_SIZE:
                _mark_budget_truncated(state, "max_total_size")
                stack.clear()
                break

            _record_scan_entry(
                state,
                ScanEntry(
                    type="file",
                    name=name,
                    path=_relative_posix(child_path, root),
                    suffix=child_path.suffix,
                    depth=depth + 1,
                    size=file_size,
                )
            )

    state.budget["total_size"] = state.total_size
    summary = _summary_from_state(state)
    metadata = _metadata_from_state(state)
    signals = _signals_from_state(state, metadata)
    focus_paths = _focus_paths_from_state(state)
    hot_directories = _hot_directories_from_state(state)
    return summary, metadata, signals, focus_paths, hot_directories


def _record_scan_entry(state: ScanState, entry: ScanEntry) -> None:
    compact = entry.as_dict()
    path_parts = tuple(part.casefold() for part in Path(entry.path).parts)
    name_fold = entry.name.casefold()

    if entry.depth == 1:
        if entry.type == "directory":
            state.top_level_dirs.add(entry.name)
        else:
            state.top_level_files.add(entry.name)

    if entry.type == "directory":
        if entry.path != ".":
            state.total_dirs += 1
        state.dir_names.add(name_fold)
    else:
        state.total_files += 1
        state.total_size += entry.size
        state.extension_counts[entry.suffix or "<none>"] += 1
        state.file_names.add(name_fold)
        _record_metadata_entry(state, compact)

    _record_path_flags(state, entry)
    _record_focus_entry(state, compact, path_parts)


def _record_metadata_entry(state: ScanState, entry: dict[str, Any]) -> None:
    name = entry["name"]
    if name in MANIFEST_FILES:
        _append_limited(state.manifest_files, _compact_entry(entry), 80)
    if name in CONFIG_FILE_NAMES:
        _append_limited(state.config_files, _compact_entry(entry), 80)
    if name in DOCUMENTATION_NAMES or name.casefold().startswith("readme"):
        _append_limited(state.documentation_files, _compact_entry(entry), 80)
    if _has_path_keyword(entry["path"], FOCUS_RULES["test"]["dir_keywords"]):
        _append_limited(state.test_paths, _compact_entry(entry), 120)


def _record_path_flags(state: ScanState, entry: ScanEntry) -> None:
    path_fold = entry.path.casefold()
    if path_fold.endswith("docker-compose.yml") or path_fold.endswith("docker-compose.yaml"):
        state.path_flags.add("docker-compose")
    if path_fold.endswith("phpunit.xml"):
        state.path_flags.add("phpunit")
    if entry.suffix.casefold() == ".twig":
        state.path_flags.add("twig-template")
    if entry.name == "services.yaml":
        state.path_flags.add("service-container")


def _record_focus_entry(
    state: ScanState,
    entry: dict[str, Any],
    path_parts: tuple[str, ...],
) -> None:
    for kind, rule in FOCUS_RULES.items():
        if kind == "test":
            continue
        if not _matches_focus_kind(entry, kind, path_parts=path_parts):
            continue
        key = (entry["path"], kind)
        state.focus_items[key] = {
            "path": entry["path"],
            "type": entry["type"],
            "kind": kind,
            "priority": str(rule["priority"]),
            "reason": _focus_reason(entry, kind),
        }
        parent = _parent_path(entry["path"])
        if parent != ".":
            state.hot_directory_counts[parent] += 1


def _mark_budget_truncated(state: ScanState, reason: str) -> None:
    state.budget["truncated"] = True
    if not state.budget.get("reason"):
        state.budget["reason"] = reason


def _summary_from_state(state: ScanState) -> dict[str, Any]:
    return {
        "total_files": state.total_files,
        "total_dirs": state.total_dirs,
        "total_size": state.total_size,
        "budget": state.budget,
        "top_level_dirs": sorted(state.top_level_dirs),
        "top_level_files": sorted(state.top_level_files),
        "file_extensions": dict(state.extension_counts.most_common()),
    }


def _metadata_from_state(state: ScanState) -> dict[str, Any]:
    return {
        "manifest_files": state.manifest_files,
        "config_files": state.config_files,
        "documentation_files": state.documentation_files,
        "test_paths": state.test_paths,
    }


def _signals_from_state(
    state: ScanState,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    focus_paths = _focus_paths_from_state(state)
    return {
        "languages": _detect_languages(dict(state.extension_counts)),
        "package_managers": _detect_package_managers(metadata["manifest_files"]),
        "architecture_hints": _detect_architecture_hints_from_state(state),
        "framework_hints": _detect_framework_hints_from_state(state, metadata),
        "security_relevant_paths": {
            kind: [
                _compact_focus_item(item)
                for item in focus_paths
                if item.get("kind") == kind
            ][:80]
            for kind in FOCUS_RULES
            if kind != "test"
        },
    }


def _focus_paths_from_state(state: ScanState) -> list[dict[str, str]]:
    return sorted(
        state.focus_items.values(),
        key=lambda item: (_priority_rank(item["priority"]), item["path"], item["kind"]),
    )[:120]


def _hot_directories_from_state(state: ScanState) -> list[dict[str, Any]]:
    return [
        {"path": path, "signals": count}
        for path, count in state.hot_directory_counts.most_common(40)
    ]


def _build_deterministic_profile(
    signals: dict[str, Any],
    focus_paths: list[dict[str, str]],
    hot_directories: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "languages": signals.get("languages", []),
        "framework_hints": signals.get("framework_hints", []),
        "architecture_hints": signals.get("architecture_hints", []),
        "attack_surfaces": _attack_surfaces_from_focus_paths(focus_paths),
        "hot_directories": hot_directories,
    }


def _detect_architecture_hints_from_state(state: ScanState) -> list[dict[str, str]]:
    hints = []
    dir_names = state.dir_names

    if {"controllers", "services"} <= dir_names:
        hints.append({"style": "layered", "reason": "controllers and services directories exist"})
    if {"handlers", "actions"} <= dir_names:
        hints.append({"style": "action-handler", "reason": "actions and handlers directories exist"})
    if "docker-compose" in state.path_flags:
        hints.append({"style": "containerized", "reason": "docker compose configuration exists"})
    if "templates" in dir_names or "views" in dir_names:
        hints.append({"style": "server-rendered", "reason": "template/view directories exist"})
    if "plugins" in dir_names or "tools" in dir_names:
        hints.append({"style": "extension-based", "reason": "plugin/tool directories exist"})

    return hints


def _detect_framework_hints_from_state(
    state: ScanState,
    metadata: dict[str, Any],
) -> list[dict[str, str]]:
    hints = []
    names = state.file_names

    if "composer.json" in names:
        hints.append({"name": "php-composer", "reason": "composer.json exists"})
    if "package.json" in names:
        hints.append({"name": "node-tooling", "reason": "package.json exists"})
    if "twig-template" in state.path_flags:
        hints.append({"name": "twig-template", "reason": "twig templates exist"})
    if "service-container" in state.path_flags:
        hints.append({"name": "service-container", "reason": "services.yaml exists"})
    if "phpunit" in state.path_flags:
        hints.append({"name": "phpunit", "reason": "phpunit.xml exists"})

    return hints


def _attack_surfaces_from_focus_paths(focus_paths: list[dict[str, str]]) -> list[str]:
    surface_by_kind = {
        "auth": "auth",
        "database": "sql-access",
        "file-io": "upload",
        "template": "template-render",
        "command": "command-execution",
        "integration": "http-client",
    }
    return _unique(
        surface_by_kind[item["kind"]]
        for item in focus_paths
        if item.get("kind") in surface_by_kind
    )


def _compact_focus_item(item: dict[str, str]) -> dict[str, str]:
    return {
        "path": item["path"],
        "type": item["type"],
        "priority": item["priority"],
        "reason": item["reason"],
    }


def _append_limited(items: list[dict[str, Any]], item: dict[str, Any], limit: int) -> None:
    if len(items) < limit:
        items.append(item)


def _build_scan_plan(
    focus_paths: list[dict[str, str]],
    signals: dict[str, Any],
) -> dict[str, Any]:
    recommended_order = [
        item
        for item in focus_paths
        if item["priority"] in {"high", "medium"}
    ][:40]

    return {
        "recommended_order": recommended_order,
        "strategy": [
            "review entrypoint paths before services and storage layers",
            "prioritize auth, database, file-io, command, and template paths",
            "use metadata and manifest files to identify framework-specific protections",
        ],
        "notes": _scan_plan_notes(signals),
    }


def _build_agent_input(tree: dict[str, Any]) -> dict[str, Any]:
    #----------- TreeScan 输入瘦身：保留摘要、信号和顶层目录画像，避免把整棵树原样送给 Agent ------------#
    return {
        "schema_version": "defectmine.treescan.agent_input.v1",
        "condensed_profile": _build_condensed_profile(tree),
    }


def _build_condensed_profile(tree: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_schema_version": tree.get("schema_version"),
        "root": tree.get("root", {}),
        "summary": _compact_summary(tree.get("summary", {})),
        "metadata": _compact_metadata(tree.get("metadata", {})),
        "signals": _compact_signals(tree.get("signals", {})),
        "focus_paths": tree.get("focus_paths", [])[:24],
        "scan_plan": _compact_scan_plan(tree.get("scan_plan", {})),
        "hot_directories": tree.get("hot_directories", [])[:20],
        "deterministic": tree.get("deterministic", {}),
    }


#----------- TreeScan 结构压缩器：把大数组裁成更短的项目地图摘要 ------------#
def _compact_summary(summary: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}

    return {
        "total_files": summary.get("total_files", 0),
        "total_dirs": summary.get("total_dirs", 0),
        "top_level_dirs": summary.get("top_level_dirs", [])[:12],
        "top_level_files": summary.get("top_level_files", [])[:12],
        "file_extensions": dict(list(summary.get("file_extensions", {}).items())[:8]),
    }


def _compact_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}

    return {
        "manifest_files": metadata.get("manifest_files", [])[:8],
        "config_files": metadata.get("config_files", [])[:8],
        "documentation_files": metadata.get("documentation_files", [])[:8],
        "test_paths": metadata.get("test_paths", [])[:8],
    }


def _compact_signals(signals: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(signals, dict):
        return {}

    security = signals.get("security_relevant_paths", {})
    if not isinstance(security, dict):
        security = {}

    return {
        "languages": signals.get("languages", [])[:6],
        "package_managers": signals.get("package_managers", [])[:6],
        "architecture_hints": signals.get("architecture_hints", [])[:6],
        "framework_hints": signals.get("framework_hints", [])[:8],
        "security_relevant_paths": {
            key: value[:6] if isinstance(value, list) else value
            for key, value in security.items()
        },
    }


def _compact_scan_plan(scan_plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(scan_plan, dict):
        return {}

    recommended_order = scan_plan.get("recommended_order", [])
    if isinstance(recommended_order, list):
        recommended_order = recommended_order[:12]

    notes = scan_plan.get("notes", [])
    if isinstance(notes, list):
        notes = notes[:6]

    strategy = scan_plan.get("strategy", [])
    if isinstance(strategy, list):
        strategy = strategy[:3]

    return {
        "recommended_order": recommended_order,
        "strategy": strategy,
        "notes": notes,
    }


def _iter_scandir(path: Path) -> Iterable[os.DirEntry[str]]:
    try:
        with os.scandir(path) as iterator:
            yield from iterator
    except (OSError, PermissionError):
        return


def _is_inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def _parent_path(path: str) -> str:
    parent = Path(path).parent.as_posix()
    return "." if parent == "." else parent


def _compact_entry(entry: dict[str, Any]) -> dict[str, str]:
    result = {
        "path": entry["path"],
        "name": entry["name"],
        "type": entry["type"],
    }
    if entry.get("suffix"):
        result["suffix"] = entry["suffix"]
    return result


def _detect_languages(extension_counts: dict[str, int]) -> list[dict[str, Any]]:
    language_counts: Counter[str] = Counter()
    for suffix, count in extension_counts.items():
        language = LANGUAGE_BY_SUFFIX.get(suffix)
        if language:
            language_counts[language] += count

    total = sum(language_counts.values()) or 1
    return [
        {
            "name": language,
            "files": count,
            "ratio": round(count / total, 4),
        }
        for language, count in language_counts.most_common()
    ]


def _detect_package_managers(
    manifest_files: list[dict[str, str]],
) -> list[dict[str, str]]:
    managers = []
    for entry in manifest_files:
        ecosystem = MANIFEST_FILES.get(entry["name"])
        if ecosystem:
            managers.append({"ecosystem": ecosystem, "path": entry["path"]})
    return managers


def _matches_focus_kind(
    entry: dict[str, Any],
    kind: str,
    *,
    path_parts: tuple[str, ...] | None = None,
) -> bool:
    path = entry["path"]
    name_stem = Path(entry["name"]).stem.casefold()
    rule = FOCUS_RULES.get(kind, {})
    dir_keywords = rule.get("dir_keywords", set())
    file_keywords = rule.get("file_keywords", set())

    if _has_path_keyword(path, dir_keywords, path_parts=path_parts):
        return True
    if entry["type"] == "file" and any(keyword in name_stem for keyword in file_keywords):
        return True

    return False


def _focus_reason(entry: dict[str, Any], kind: str) -> str:
    if entry["type"] == "directory":
        return f"directory name or path suggests {kind} behavior"
    return f"file name, suffix, or path suggests {kind} behavior"


def _scan_plan_notes(signals: dict[str, Any]) -> list[str]:
    notes = []
    languages = [item["name"] for item in signals["languages"][:3]]
    if languages:
        notes.append(f"dominant languages: {', '.join(languages)}")
    package_managers = [item["ecosystem"] for item in signals["package_managers"]]
    if package_managers:
        notes.append(f"package metadata detected: {', '.join(package_managers)}")
    if not notes:
        notes.append("limited framework metadata detected; rely on focus_paths first")
    return notes


def _has_path_keyword(
    path: str,
    keywords: set[str],
    *,
    path_parts: tuple[str, ...] | None = None,
) -> bool:
    parts = path_parts or tuple(part.casefold() for part in Path(path).parts)
    return any(part in keywords for part in parts)


def _path_depth(path: str) -> int:
    if path == ".":
        return 0
    return len(Path(path).parts)


def _priority_rank(priority: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(priority, 3)


def _relative_posix(path: Path, root: Path) -> str:
    if path == root:
        return "."
    return path.relative_to(root).as_posix()


def _resolve_artifacts_dir(root: Path, artifacts_dir: str | Path | None) -> Path:
    if artifacts_dir is None:
        return (root / ARTIFACTS_DIRNAME).resolve()

    path = Path(artifacts_dir).expanduser()
    if not path.is_absolute():
        path = root / path

    return path.resolve()


def _write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(text + "\n", encoding="utf-8")


def _write_text(data: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def _report_progress(
    progress_reporter: ProgressReporter | None,
    payload: dict[str, Any],
) -> None:
    if progress_reporter is None:
        return
    progress_reporter(payload)


def _parse_treescan_profile(raw_profile: str) -> dict[str, Any]:
    try:
        return _normalize_treescan_profile(_parse_json_object(raw_profile))
    except json.JSONDecodeError as exc:
        recovered = _recover_treescan_profile(raw_profile, exc)
        if recovered is not None:
            return recovered
        return _invalid_agent_json_profile(raw_profile, exc)
    except ValueError as exc:
        recovered = _recover_treescan_profile(raw_profile, exc)
        if recovered is not None:
            return recovered
        return _invalid_agent_json_profile(raw_profile, exc)


def _invalid_agent_json_profile(raw_profile: str, error: Exception) -> dict[str, Any]:
    return {
        "status": "invalid_json",
        "error": str(error),
        "raw_output_artifact": TREESCAN_RAW_PROFILE_FILENAME,
        "raw_output_preview": raw_profile[:2000],
        "project_name": "unknown",
        "project_function": "unknown",
        "project_type": "unknown",
        "technology_stack": {
            "backend": [],
            "frontend": [],
            "database": [],
            "data": [],
            "integration": [],
            "file_io": [],
        },
        "project_summary": "TreeScan Agent output could not be parsed as strict JSON. Check the raw output artifact for details.",
        "project_understanding": {
            "overview": "unknown",
            "entrypoint_examples": [],
            "focus_modules": [],
            "attack_surfaces": [],
        },
        "scanner_hints": _empty_scanner_hints(),
        "architecture_style": ["unknown"],
        "entrypoints": [],
        "execution_flows": [],
        "service_boundaries": [],
        "api_surfaces": [],
        "data_paths": [],
        "auth_related_paths": [],
        "database_related_paths": [],
        "file_operation_paths": [],
        "template_related_paths": [],
        "external_integration_paths": [],
        "potential_attack_surfaces": [],
        "high_value_modules": [],
        "confidence": {
            "overall": "low",
            "notes": [
                "TreeScan Agent returned content that could not be parsed as strict JSON.",
                f"See {TREESCAN_RAW_PROFILE_FILENAME} for the raw model output.",
            ],
        },
    }


def _profile_state_summary(profile: dict[str, Any]) -> dict[str, Any]:
    stack = profile.get("technology_stack", {})
    if not isinstance(stack, dict):
        stack = {}

    return {
        "status": profile.get("status", "ok"),
        "project_name": profile.get("project_name", "unknown"),
        "project_function": profile.get("project_function", "unknown"),
        "project_type": profile.get("project_type", "unknown"),
        "project_summary": profile.get("project_summary", ""),
        "project_understanding": profile.get("project_understanding", {}),
        "architecture_style": profile.get("architecture_style", []),
        "backend": stack.get("backend", []),
        "frontend": stack.get("frontend", []),
        "database": stack.get("database", stack.get("data", [])),
        "scanner_hints": profile.get("scanner_hints", {}),
        "confidence": profile.get("confidence", {}),
    }


#----------- TreeScan 结果恢复：尽量修复截断 JSON，并统一成 CLI 使用的 schema ------------#
def _recover_treescan_profile(raw_profile: str, error: Exception) -> dict[str, Any] | None:
    repaired = _repair_truncated_json_object(raw_profile)
    if repaired is not None:
        normalized = _normalize_treescan_profile(repaired)
        normalized["status"] = "recovered_json"
        normalized["parse_error"] = str(error)
        return normalized

    salvaged = _salvage_profile_from_partial_json(raw_profile)
    if salvaged is not None:
        normalized = _normalize_treescan_profile(salvaged)
        normalized["status"] = "salvaged_json"
        normalized["parse_error"] = str(error)
        return normalized

    return None


def _repair_truncated_json_object(raw_profile: str) -> dict[str, Any] | None:
    cleaned = raw_profile.strip()
    if cleaned.startswith("```"):
        cleaned = _strip_code_fence(cleaned)

    candidate = re.sub(r",\s*$", "", cleaned)
    stack: list[str] = []
    in_string = False
    escape = False

    for char in candidate:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue
        if char in "{[":
            stack.append(char)
        elif char == "}" and stack and stack[-1] == "{":
            stack.pop()
        elif char == "]" and stack and stack[-1] == "[":
            stack.pop()

    if in_string:
        candidate += '"'

    while candidate.endswith(","):
        candidate = candidate[:-1].rstrip()

    closing = []
    for opener in reversed(stack):
        closing.append("}" if opener == "{" else "]")
    candidate += "".join(closing)

    try:
        parsed = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return None

    return parsed if isinstance(parsed, dict) else None


def _salvage_profile_from_partial_json(raw_profile: str) -> dict[str, Any] | None:
    fields = {
        "architecture_style": _extract_string_array_field(raw_profile, "architecture_style"),
        "entrypoints": _extract_object_array_field(raw_profile, "entrypoints"),
        "service_boundaries": _extract_object_array_field(raw_profile, "service_boundaries"),
        "api_surfaces": _extract_object_array_field(raw_profile, "api_surfaces"),
        "data_paths": _extract_object_array_field(raw_profile, "data_paths"),
        "auth_related_paths": _extract_object_array_field(raw_profile, "auth_related_paths"),
        "database_related_paths": _extract_object_array_field(raw_profile, "database_related_paths"),
        "file_operation_paths": _extract_object_array_field(raw_profile, "file_operation_paths"),
        "template_related_paths": _extract_object_array_field(raw_profile, "template_related_paths"),
        "external_integration_paths": _extract_object_array_field(raw_profile, "external_integration_paths"),
        "potential_attack_surfaces": _extract_string_array_field(raw_profile, "potential_attack_surfaces"),
        "scanner_hints": _extract_object_field(raw_profile, "scanner_hints"),
        "high_value_modules": _extract_object_array_field(raw_profile, "high_value_modules"),
        "execution_flows": _extract_object_array_field(raw_profile, "execution_flows"),
        "confidence": _extract_confidence_field(raw_profile),
    }

    has_signal = any(
        value
        for key, value in fields.items()
        if key != "confidence"
    )
    if not has_signal:
        return None
    return fields


def _extract_string_array_field(raw_profile: str, field_name: str) -> list[str]:
    block = _extract_array_block(raw_profile, field_name)
    if not block:
        return []
    return re.findall(r'"((?:\\.|[^"\\])*)"', block)


def _extract_object_array_field(raw_profile: str, field_name: str) -> list[dict[str, Any]]:
    block = _extract_array_block(raw_profile, field_name)
    if not block:
        return []

    repaired = block.rstrip()
    while repaired.endswith(","):
        repaired = repaired[:-1].rstrip()
    repaired += "]"

    try:
        parsed = json.loads(repaired)
    except (json.JSONDecodeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _extract_object_field(raw_profile: str, field_name: str) -> dict[str, Any]:
    block = _extract_object_block(raw_profile, field_name)
    if not block:
        return {}

    try:
        parsed = json.loads(block)
    except (json.JSONDecodeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _extract_array_block(raw_profile: str, field_name: str) -> str:
    marker = f'"{field_name}"'
    start = raw_profile.find(marker)
    if start == -1:
        return ""

    array_start = raw_profile.find("[", start)
    if array_start == -1:
        return ""

    depth = 0
    in_string = False
    escape = False
    for index in range(array_start, len(raw_profile)):
        char = raw_profile[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return raw_profile[array_start : index + 1]

    return raw_profile[array_start:]


def _extract_object_block(raw_profile: str, field_name: str) -> str:
    marker = f'"{field_name}"'
    start = raw_profile.find(marker)
    if start == -1:
        return ""

    object_start = raw_profile.find("{", start)
    if object_start == -1:
        return ""

    depth = 0
    in_string = False
    escape = False
    for index in range(object_start, len(raw_profile)):
        char = raw_profile[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\": 
                escape = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return raw_profile[object_start : index + 1]

    return raw_profile[object_start:]


def _extract_confidence_field(raw_profile: str) -> dict[str, Any]:
    match = re.search(r'"overall"\s*:\s*"([^"]+)"', raw_profile)
    overall = match.group(1) if match else "low"
    notes = _extract_string_array_field(raw_profile, "notes")
    return {
        "overall": overall,
        "notes": notes,
    }


def _normalize_treescan_profile(profile: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(profile)
    stack = profile.get("technology_stack", {})
    if not isinstance(stack, dict):
        stack = {}

    llm_inferred = {
        "project_name": str(profile.get("project_name", "unknown")).strip() or "unknown",
        "project_function": str(profile.get("project_function", "unknown")).strip() or "unknown",
        "project_type": str(profile.get("project_type", "unknown")).strip() or "unknown",
        "technology_stack": {
            "backend": _ensure_string_list(stack.get("backend")),
            "frontend": _ensure_string_list(stack.get("frontend")),
            "database": _ensure_string_list(stack.get("database")) or _ensure_string_list(stack.get("data")),
            "integration": _ensure_string_list(stack.get("integration")),
            "file_io": _ensure_string_list(stack.get("file_io")),
        },
        "project_summary": str(profile.get("project_summary", "")).strip(),
        "project_understanding": profile.get("project_understanding", {}),
        "scanner_hints": profile.get("scanner_hints", {}),
        "confidence": profile.get("confidence", {}),
    }

    scanner_inferred = _build_scanner_inferred_profile(profile)
    deterministic = {
        "technology_stack": {
            "backend": _infer_backend_stack(profile),
            "frontend": _infer_frontend_stack(profile),
            "database": _infer_database_stack(profile),
            "integration": _infer_integration_stack(profile.get("external_integration_paths", [])),
            "file_io": _infer_file_stack(profile.get("file_operation_paths", [])),
        },
        "attack_surfaces": _build_attack_surface_labels(profile),
        "focus_modules": _build_focus_modules(profile),
        "scanner_hints": _build_scanner_hints(profile),
    }

    backend = _unique(llm_inferred["technology_stack"]["backend"] or deterministic["technology_stack"]["backend"])
    frontend = _unique(llm_inferred["technology_stack"]["frontend"] or deterministic["technology_stack"]["frontend"])
    database = _unique(
        llm_inferred["technology_stack"]["database"]
        or deterministic["technology_stack"]["database"]
    )
    integration = _unique(
        llm_inferred["technology_stack"]["integration"]
        or deterministic["technology_stack"]["integration"]
    )
    file_io = _unique(
        llm_inferred["technology_stack"]["file_io"]
        or deterministic["technology_stack"]["file_io"]
    )

    normalized["project_name"] = llm_inferred["project_name"] or _infer_project_name(profile)
    normalized["project_function"] = llm_inferred["project_function"] or _infer_project_function(profile)
    normalized["project_type"] = llm_inferred["project_type"] or _infer_project_type(profile, backend, frontend)
    normalized["technology_stack"] = {
        "backend": backend,
        "frontend": frontend,
        "database": database,
        "data": database,
        "integration": integration,
        "file_io": file_io,
    }
    normalized["project_summary"] = llm_inferred["project_summary"] or _build_project_summary(normalized)
    normalized["llm_inferred"] = llm_inferred
    normalized["scanner_inferred"] = scanner_inferred
    normalized["deterministic"] = deterministic
    normalized["project_understanding"] = {
        "overview": normalized["project_summary"],
        "entrypoint_examples": _entrypoint_examples(profile)[:6],
        "focus_modules": scanner_inferred.get("focus_modules", []),
        "attack_surfaces": deterministic["attack_surfaces"],
        "repository_shape": str(profile.get("repository_shape", "")).strip(),
        "interface_shape": str(profile.get("interface_shape", "")).strip(),
        "project_maturity": str(profile.get("project_maturity", "")).strip(),
    }
    normalized["scanner_hints"] = deterministic["scanner_hints"]
    return normalized


def _enrich_profile_from_tree(profile: dict[str, Any], tree: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(profile)
    llm_inferred = _ensure_llm_inferred(normalized)
    deterministic = _deterministic_profile_from_tree(tree, normalized)
    resolved_stack = _resolve_technology_stack(
        llm_inferred.get("technology_stack", {}),
        deterministic.get("technology_stack", {}),
    )

    normalized["technology_stack"] = resolved_stack
    normalized["project_name"] = (
        _known_text(llm_inferred.get("project_name"))
        or _known_text(deterministic.get("project_name_from_root"))
        or "unknown"
    )
    normalized["project_function"] = (
        _known_text(llm_inferred.get("project_function"))
        or _known_text(_infer_project_function(normalized))
        or "unknown"
    )
    normalized["project_type"] = (
        _known_text(llm_inferred.get("project_type"))
        or _known_text(_infer_project_type(normalized, resolved_stack["backend"], resolved_stack["frontend"]))
        or "unknown"
    )

    #----------- TreeScan 认知分桶：LLM、本地确定性推断、Scanner 提示分开保存，顶层只保留兼容展示视图 ------------#
    scanner_inferred = _scanner_inferred_profile_from_sources(normalized, deterministic, tree)
    normalized["llm_inferred"] = llm_inferred
    normalized["deterministic"] = deterministic
    normalized["scanner_inferred"] = scanner_inferred
    normalized["scanner_hints"] = scanner_inferred["scanner_hints"]
    normalized["project_summary"] = (
        _known_text(llm_inferred.get("project_summary"))
        or _build_project_summary(normalized)
    )
    normalized["project_understanding"] = {
        "overview": normalized["project_summary"],
        "entrypoint_examples": _entrypoint_examples(normalized)[:6],
        "focus_modules": scanner_inferred.get("focus_modules", [])[:8],
        "attack_surfaces": scanner_inferred.get("attack_surfaces", [])[:8],
        "repository_shape": str(normalized.get("repository_shape", "")).strip(),
        "interface_shape": str(normalized.get("interface_shape", "")).strip(),
        "project_maturity": str(normalized.get("project_maturity", "")).strip(),
    }
    return normalized


def _build_scanner_inferred_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "focus_modules": _build_focus_modules(profile),
        "attack_surfaces": _build_attack_surface_labels(profile),
        "scanner_hints": _build_scanner_hints(profile),
        "hot_directories": [],
    }


def _ensure_llm_inferred(profile: dict[str, Any]) -> dict[str, Any]:
    llm_inferred = _object_or_empty(profile.get("llm_inferred"))
    profile_stack = _object_or_empty(profile.get("technology_stack"))
    llm_stack = _object_or_empty(llm_inferred.get("technology_stack"))

    return {
        "project_name": _known_text(llm_inferred.get("project_name")) or _known_text(profile.get("project_name")) or "unknown",
        "project_function": _known_text(llm_inferred.get("project_function")) or _known_text(profile.get("project_function")) or "unknown",
        "project_type": _known_text(llm_inferred.get("project_type")) or _known_text(profile.get("project_type")) or "unknown",
        "technology_stack": {
            "backend": _known_string_list(llm_stack.get("backend") or profile_stack.get("backend")),
            "frontend": _known_string_list(llm_stack.get("frontend") or profile_stack.get("frontend")),
            "database": _known_string_list(
                llm_stack.get("database")
                or llm_stack.get("data")
                or profile_stack.get("database")
                or profile_stack.get("data")
            ),
            "integration": _known_string_list(llm_stack.get("integration") or profile_stack.get("integration")),
            "file_io": _known_string_list(llm_stack.get("file_io") or profile_stack.get("file_io")),
        },
        "project_summary": _known_text(llm_inferred.get("project_summary")) or _known_text(profile.get("project_summary")),
        "project_understanding": _object_or_empty(llm_inferred.get("project_understanding")) or _object_or_empty(profile.get("project_understanding")),
        "scanner_hints": _object_or_empty(llm_inferred.get("scanner_hints")) or _object_or_empty(profile.get("scanner_hints")),
        "confidence": _object_or_empty(llm_inferred.get("confidence")) or _object_or_empty(profile.get("confidence")),
    }


def _deterministic_profile_from_tree(tree: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    deterministic = _object_or_empty(tree.get("deterministic"))
    signals = _object_or_empty(tree.get("signals"))

    return {
        "project_name_from_root": _infer_project_name_from_tree(tree, profile),
        "technology_stack": _technology_stack_from_tree(tree),
        "languages": deterministic.get("languages", signals.get("languages", [])),
        "framework_hints": deterministic.get("framework_hints", signals.get("framework_hints", [])),
        "architecture_hints": deterministic.get("architecture_hints", signals.get("architecture_hints", [])),
        "attack_surfaces": _ensure_string_list(deterministic.get("attack_surfaces")),
        "hot_directories": deterministic.get("hot_directories", tree.get("hot_directories", [])),
        "manifest_files": _object_or_empty(tree.get("metadata")).get("manifest_files", []),
    }


def _technology_stack_from_tree(tree: dict[str, Any]) -> dict[str, list[str]]:
    language_names = _language_names_from_tree(tree)
    focus_kinds = {
        str(item.get("kind", "")).strip()
        for item in tree.get("focus_paths", [])
        if isinstance(item, dict)
    }

    backend: list[str] = []
    frontend: list[str] = []
    database: list[str] = []
    integration: list[str] = []
    file_io: list[str] = []

    if "php" in language_names:
        backend.append("PHP")
    if "python" in language_names:
        backend.append("Python")
    if "java" in language_names:
        backend.append("Java")
    if "go" in language_names:
        backend.append("Go")
    if "ruby" in language_names:
        backend.append("Ruby")
    if "twig" in language_names:
        backend.append("Twig")
        frontend.append("HTML")
    if "html" in language_names:
        frontend.append("HTML")
    if "css" in language_names:
        frontend.append("CSS")
    if {"javascript", "typescript"} & language_names:
        frontend.append("JavaScript")
    if "sql" in language_names or "database" in focus_kinds:
        database.append("SQL Database")
    if "integration" in focus_kinds:
        integration.append("HTTP API")
    if "file-io" in focus_kinds:
        file_io.append("Upload/File Storage")

    return {
        "backend": _unique(backend),
        "frontend": _unique(frontend),
        "database": _unique(database),
        "data": _unique(database),
        "integration": _unique(integration),
        "file_io": _unique(file_io),
    }


def _language_names_from_tree(tree: dict[str, Any]) -> set[str]:
    signals = _object_or_empty(tree.get("signals"))
    languages = signals.get("languages", [])
    if not isinstance(languages, list):
        return set()
    return {
        str(item.get("name", "")).casefold()
        for item in languages
        if isinstance(item, dict) and item.get("name")
    }


def _resolve_technology_stack(
    llm_stack: Any,
    deterministic_stack: Any,
) -> dict[str, list[str]]:
    llm_stack = _object_or_empty(llm_stack)
    deterministic_stack = _object_or_empty(deterministic_stack)
    database = _known_string_list(llm_stack.get("database") or llm_stack.get("data"))
    if not database:
        database = _known_string_list(deterministic_stack.get("database") or deterministic_stack.get("data"))

    return {
        "backend": _known_string_list(llm_stack.get("backend")) or _known_string_list(deterministic_stack.get("backend")),
        "frontend": _known_string_list(llm_stack.get("frontend")) or _known_string_list(deterministic_stack.get("frontend")),
        "database": database,
        "data": database,
        "integration": _known_string_list(llm_stack.get("integration")) or _known_string_list(deterministic_stack.get("integration")),
        "file_io": _known_string_list(llm_stack.get("file_io")) or _known_string_list(deterministic_stack.get("file_io")),
    }


def _scanner_inferred_profile_from_sources(
    profile: dict[str, Any],
    deterministic: dict[str, Any],
    tree: dict[str, Any],
) -> dict[str, Any]:
    existing = _object_or_empty(profile.get("scanner_inferred"))
    focus_modules = _unique(
        _known_string_list(existing.get("focus_modules"))
        + _build_focus_modules(profile)
        + _infer_priority_paths(profile, tree)
    )[:20]
    attack_surfaces = _unique(
        _known_string_list(existing.get("attack_surfaces"))
        + _build_attack_surface_labels(profile)
        + _ensure_string_list(deterministic.get("attack_surfaces"))
    )

    return {
        "focus_modules": focus_modules,
        "attack_surfaces": attack_surfaces,
        "scanner_hints": _build_scanner_hints(profile, tree),
        "hot_directories": deterministic.get("hot_directories", []),
    }


def _infer_project_name(profile: dict[str, Any]) -> str:
    search_values = (
        _flatten_profile_strings(profile.get("entrypoints"))
        + _flatten_profile_strings(profile.get("service_boundaries"))
        + _flatten_profile_strings(profile.get("high_value_modules"))
        + _flatten_profile_strings(profile.get("template_related_paths"))
        + [str(profile.get("summary", ""))]
        + [str(profile.get("description", ""))]
    )
    searchable = " ".join(search_values)
    searchable_lower = searchable.lower()

    if "wakka.php" in searchable_lower or "yeswiki" in searchable_lower:
        return "YesWiki"
    explicit = _first_named_entity(searchable)
    return explicit or "unknown"


def _infer_project_type(
    profile: dict[str, Any],
    backend: list[str],
    frontend: list[str],
) -> str:
    architecture = {item.lower() for item in _ensure_string_list(profile.get("architecture_style"))}
    template_paths = _flatten_profile_strings(profile.get("template_related_paths"))
    entrypoints = _flatten_profile_strings(profile.get("entrypoints"))

    if "server-rendered" in architecture or template_paths:
        return "Web 应用"
    if backend and (frontend or entrypoints):
        return "Web 应用"
    if frontend and not backend:
        return "前端应用"
    return "unknown"


def _infer_backend_stack(profile: dict[str, Any]) -> list[str]:
    values: list[str] = []
    joined = " ".join(
        _flatten_profile_strings(profile.get("entrypoints"))
        + _flatten_profile_strings(profile.get("service_boundaries"))
        + _flatten_profile_strings(profile.get("high_value_modules"))
        + _flatten_profile_strings(profile.get("database_related_paths"))
    ).lower()

    if ".php" in joined or "php" in joined:
        values.append("PHP")
    if any("twig" in item.lower() for item in _flatten_profile_strings(profile.get("template_related_paths"))):
        values.append("Twig")
    if "python" in joined or ".py" in joined:
        values.append("Python")
    if "java" in joined and "javascript" not in joined:
        values.append("Java")
    if "go" in joined or ".go" in joined:
        values.append("Go")
    if "ruby" in joined or ".rb" in joined:
        values.append("Ruby")
    if "csharp" in joined or ".cs" in joined or "asp.net" in joined:
        values.append("C#")
    return _unique(values)


def _infer_frontend_stack(profile: dict[str, Any]) -> list[str]:
    values: list[str] = []
    template_paths = " ".join(_flatten_profile_strings(profile.get("template_related_paths"))).lower()
    api_surfaces = " ".join(_flatten_profile_strings(profile.get("api_surfaces"))).lower()

    if template_paths:
        values.append("HTML")
        values.append("CSS")
    if "api" in api_surfaces or "assets/javascripts" in template_paths or "javascript" in api_surfaces:
        values.append("JavaScript")
    if "react" in template_paths or "jsx" in template_paths or "tsx" in template_paths:
        values.append("React")
    if "vue" in template_paths:
        values.append("Vue")
    return _unique(values)


def _infer_data_stack(database_paths: list[Any]) -> list[str]:
    joined = " ".join(_flatten_profile_strings(database_paths)).lower()
    values: list[str] = []
    if "sql" in joined or "db" in joined or "migration" in joined:
        values.append("SQL Database")
    return _unique(values)


def _infer_integration_stack(external_paths: list[Any]) -> list[str]:
    joined = " ".join(_flatten_profile_strings(external_paths)).lower()
    values: list[str] = []
    if "api" in joined or "client" in joined or "rss" in joined:
        values.append("HTTP API")
    if "mail" in joined or "mailer" in joined:
        values.append("Email")
    return _unique(values)


def _infer_file_stack(file_paths: list[Any]) -> list[str]:
    joined = " ".join(_flatten_profile_strings(file_paths)).lower()
    values: list[str] = []
    if "upload" in joined or "attach" in joined or "files" in joined:
        values.append("Upload/File Storage")
    if "backup" in joined or "archive" in joined:
        values.append("Backup/Archive")
    return _unique(values)


#----------- TreeScan 项目理解摘要：把项目名称、功能和技术栈压缩成 CLI 可展示的自然语言概览 ------------#
def _build_project_summary(profile: dict[str, Any]) -> str:
    project_name = profile.get("project_name", "unknown")
    project_function = profile.get("project_function", "unknown")
    project_type = profile.get("project_type", "unknown")
    backend = _join_cn_list(profile.get("technology_stack", {}).get("backend", []))
    frontend = _join_cn_list(profile.get("technology_stack", {}).get("frontend", []))
    database = _join_cn_list(profile.get("technology_stack", {}).get("database", []))
    architecture = _join_cn_list(profile.get("architecture_style", []))
    entrypoints = _join_cn_list(_entrypoint_examples(profile)[:4])
    attack_surfaces = _join_cn_list(_build_attack_surface_labels(profile)[:4])

    parts = [
        f"该项目可归纳为 {project_type}" if project_type != "unknown" else "",
        f"主要功能为 {project_function}" if project_function != "unknown" else "",
        f"核心后端技术为 {backend}" if backend != "unknown" else "",
        f"前端形态为 {frontend}" if frontend != "unknown" else "",
        f"数据库相关技术为 {database}" if database != "unknown" else "",
        f"结构风格偏向 {architecture}" if architecture != "unknown" else "",
        f"主要入口集中在 {entrypoints}" if entrypoints != "unknown" else "",
        f"需要重点关注的攻击面包括 {attack_surfaces}" if attack_surfaces != "unknown" else "",
    ]
    parts = [part for part in parts if part]
    if project_name != "unknown":
        parts.insert(0, f"{project_name}。")
    return "，".join(parts) if parts else "当前无法稳定总结该项目结构。"


def _build_focus_modules(profile: dict[str, Any]) -> list[str]:
    modules = _path_values(profile.get("high_value_modules"))
    if modules:
        return _unique(modules)[:6]

    fallbacks = (
        _path_values(profile.get("service_boundaries"))
        + _path_values(profile.get("auth_related_paths"))
        + _path_values(profile.get("database_related_paths"))
    )
    return _unique(fallbacks)[:6]


def _build_attack_surface_labels(profile: dict[str, Any]) -> list[str]:
    values = _ensure_string_list(profile.get("potential_attack_surfaces"))
    if values:
        return values

    inferred: list[str] = []
    if _flatten_profile_strings(profile.get("file_operation_paths")):
        inferred.append("file-io")
    if _flatten_profile_strings(profile.get("template_related_paths")):
        inferred.append("template-render")
    if _flatten_profile_strings(profile.get("database_related_paths")):
        inferred.append("sql-access")
    if _flatten_profile_strings(profile.get("auth_related_paths")):
        inferred.append("auth")
    return _unique(inferred)


#----------- TreeScan 扫描计划提示：把项目认知转成 Scanner 可直接消费的 sink 搜索方向 ------------#
def _build_scanner_hints(
    profile: dict[str, Any],
    tree: dict[str, Any] | None = None,
) -> dict[str, Any]:
    existing = profile.get("scanner_hints", {})
    if not isinstance(existing, dict):
        existing = {}

    sink_languages = _unique(
        _ensure_string_list(existing.get("sink_languages"))
        + _infer_sink_languages(profile, tree)
    )
    sink_categories = _unique(
        _ensure_string_list(existing.get("sink_categories"))
        + _infer_sink_categories(profile)
    )
    priority_paths = _unique(
        _ensure_string_list(existing.get("priority_paths"))
        + _infer_priority_paths(profile, tree)
    )[:40]
    entrypoint_patterns = _unique(
        _ensure_string_list(existing.get("entrypoint_patterns"))
        + _entrypoint_paths(profile)
    )[:40]
    source_patterns = _unique(
        _ensure_string_list(existing.get("source_patterns"))
        + _source_patterns_for_languages(sink_languages)
    )[:80]
    rg_include_globs = _unique(
        _ensure_string_list(existing.get("rg_include_globs"))
        + _rg_include_globs_for_languages(sink_languages)
    )
    rg_exclude_globs = _unique(
        _ensure_string_list(existing.get("rg_exclude_globs"))
        + [f"!{path}**" for path in DEFAULT_SCANNER_EXCLUDE_PATHS]
    )
    exclude_paths = _unique(
        _ensure_string_list(existing.get("exclude_paths"))
        + DEFAULT_SCANNER_EXCLUDE_PATHS
    )

    return {
        "sink_languages": sink_languages,
        "sink_categories": sink_categories,
        "priority_paths": priority_paths,
        "exclude_paths": exclude_paths,
        "entrypoint_patterns": entrypoint_patterns,
        "source_patterns": source_patterns,
        "rg_include_globs": rg_include_globs,
        "rg_exclude_globs": rg_exclude_globs,
    }


def _empty_scanner_hints() -> dict[str, list[str]]:
    return {
        "sink_languages": [],
        "sink_categories": [],
        "priority_paths": [],
        "exclude_paths": DEFAULT_SCANNER_EXCLUDE_PATHS,
        "entrypoint_patterns": [],
        "source_patterns": [],
        "rg_include_globs": [],
        "rg_exclude_globs": [f"!{path}**" for path in DEFAULT_SCANNER_EXCLUDE_PATHS],
    }


def _infer_sink_languages(
    profile: dict[str, Any],
    tree: dict[str, Any] | None,
) -> list[str]:
    values = _technology_values(profile)
    if tree:
        signals = tree.get("signals", {})
        languages = signals.get("languages", []) if isinstance(signals, dict) else []
        values.extend(
            str(item.get("name", ""))
            for item in languages
            if isinstance(item, dict)
        )

    languages: list[str] = []
    for value in values:
        normalized = LANGUAGE_ALIASES.get(value.strip().lower())
        if normalized:
            languages.append(normalized)
    return _unique(languages)


def _technology_values(profile: dict[str, Any]) -> list[str]:
    stack = profile.get("technology_stack", {})
    if not isinstance(stack, dict):
        return []

    return (
        _ensure_string_list(stack.get("backend"))
        + _ensure_string_list(stack.get("frontend"))
        + _ensure_string_list(stack.get("database"))
        + _ensure_string_list(stack.get("data"))
        + _ensure_string_list(stack.get("integration"))
        + _ensure_string_list(stack.get("file_io"))
    )


def _infer_sink_categories(profile: dict[str, Any]) -> list[str]:
    categories: list[str] = []
    attack_surfaces = _build_attack_surface_labels(profile)
    for surface in attack_surfaces:
        categories.extend(SINK_CATEGORY_BY_ATTACK_SURFACE.get(surface, []))

    if _flatten_profile_strings(profile.get("database_related_paths")):
        categories.append("sql-query")
    if _flatten_profile_strings(profile.get("file_operation_paths")):
        categories.append("file-read-write")
    if _flatten_profile_strings(profile.get("template_related_paths")):
        categories.append("template-render")
    if _flatten_profile_strings(profile.get("external_integration_paths")):
        categories.append("http-client")
    if _flatten_profile_strings(profile.get("auth_related_paths")):
        categories.append("auth")

    return _unique(categories)


def _infer_priority_paths(
    profile: dict[str, Any],
    tree: dict[str, Any] | None,
) -> list[str]:
    paths = _path_values(profile.get("high_value_modules"))
    paths.extend(_path_values(profile.get("auth_related_paths")))
    paths.extend(_path_values(profile.get("database_related_paths")))
    paths.extend(_path_values(profile.get("file_operation_paths")))
    paths.extend(_path_values(profile.get("template_related_paths")))

    if tree:
        for item in tree.get("focus_paths", [])[:80]:
            if not isinstance(item, dict):
                continue
            if item.get("priority") not in {"high", "medium"}:
                continue
            path = str(item.get("path", "")).strip()
            if path and _is_scanner_priority_path(path):
                paths.append(path)

    return _unique(path for path in paths if _is_scanner_priority_path(path))


def _is_scanner_priority_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    if not normalized:
        return False
    if any(normalized.startswith(prefix) for prefix in SCANNER_PRIORITY_EXCLUDED_PREFIXES):
        return False
    if normalized.endswith("/"):
        return True

    suffix = Path(normalized).suffix.lower()
    source_suffixes = {
        ".php",
        ".twig",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".py",
        ".java",
        ".go",
        ".rb",
        ".cs",
        ".sql",
        ".html",
        ".xml",
    }
    return suffix in source_suffixes or suffix == ""


def _entrypoint_paths(profile: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for item in profile.get("entrypoints", []):
        if isinstance(item, str) and item.strip():
            paths.append(item.strip())
            continue
        if isinstance(item, dict):
            path = str(item.get("path", "")).strip()
            if path:
                paths.append(path)
    return _unique(paths)


def _path_values(values: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(values, dict):
        path = str(values.get("path", "")).strip()
        if path:
            paths.append(path)
        for nested in values.values():
            if isinstance(nested, (list, tuple, set, dict)):
                paths.extend(_path_values(nested))
        return paths
    if isinstance(values, list):
        for item in values:
            paths.extend(_path_values(item))
        return paths
    if isinstance(values, str) and values.strip():
        paths.append(values.strip())
    return paths


def _source_patterns_for_languages(languages: list[str]) -> list[str]:
    patterns: list[str] = []
    for language in languages:
        patterns.extend(SOURCE_PATTERNS_BY_LANGUAGE.get(language, []))
    return _unique(patterns)


def _rg_include_globs_for_languages(languages: list[str]) -> list[str]:
    globs: list[str] = []
    for language in languages:
        globs.extend(RG_INCLUDE_GLOBS_BY_LANGUAGE.get(language, []))
    return _unique(globs)


#----------- TreeScan 画像补全：兼容对象数组 schema，并从目录信号推断更稳定的项目认知 ------------#
def _flatten_profile_strings(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        text = values.strip()
        return [text] if text else []
    if isinstance(values, dict):
        flattened: list[str] = []
        for value in values.values():
            flattened.extend(_flatten_profile_strings(value))
        return flattened
    if isinstance(values, (list, tuple, set)):
        flattened: list[str] = []
        for item in values:
            flattened.extend(_flatten_profile_strings(item))
        return flattened
    if isinstance(values, (int, float)) and not isinstance(values, bool):
        return [str(values)]
    return []


def _entrypoint_examples(profile: dict[str, Any]) -> list[str]:
    examples: list[str] = []
    for item in profile.get("entrypoints", []):
        if isinstance(item, str) and item.strip():
            examples.append(item.strip())
            continue
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).strip()
        entry_type = str(item.get("type", "")).strip()
        if path and entry_type:
            examples.append(f"{path} ({entry_type})")
        elif path:
            examples.append(path)
    return _unique(examples)


def _infer_project_name_from_tree(tree: dict[str, Any], profile: dict[str, Any]) -> str:
    inferred = _infer_project_name(profile)
    if inferred != "unknown":
        return inferred

    root_name = str(tree.get("root", {}).get("name", "")).strip()
    if not root_name:
        return "unknown"

    cleaned = re.sub(r"[-_]?v?\d+(?:\.\d+)*$", "", root_name, flags=re.IGNORECASE)
    cleaned = cleaned.strip("-_ .")
    if not cleaned:
        cleaned = root_name

    if cleaned.lower() == "yeswiki":
        return "YesWiki"
    if re.search(r"[A-Z][a-z]+(?:[A-Z][a-z]+)+", cleaned):
        return cleaned
    if cleaned.islower() and cleaned.isalpha():
        return cleaned.capitalize()
    return cleaned or "unknown"


def _infer_project_function(profile: dict[str, Any]) -> str:
    searchable = " ".join(
        _flatten_profile_strings(profile.get("entrypoints"))
        + _flatten_profile_strings(profile.get("service_boundaries"))
        + _flatten_profile_strings(profile.get("api_surfaces"))
        + _flatten_profile_strings(profile.get("template_related_paths"))
        + _flatten_profile_strings(profile.get("high_value_modules"))
    ).lower()

    if "wiki" in searchable:
        return "Wiki / knowledge-base platform"
    if "cms" in searchable or "content" in searchable:
        return "Content management web application"
    if "shop" in searchable or "order" in searchable or "cart" in searchable:
        return "E-commerce web application"
    if "blog" in searchable or "post" in searchable:
        return "Blog / publishing platform"
    if "admin" in searchable and "api" in searchable:
        return "Administrative web platform"
    if "plugin" in searchable or "extension" in searchable:
        return "Extensible web application with plugin architecture"
    if searchable:
        return "Web application"
    return "unknown"


def _infer_database_stack(profile: dict[str, Any]) -> list[str]:
    joined = " ".join(
        _flatten_profile_strings(profile.get("database_related_paths"))
        + _flatten_profile_strings(profile.get("data_paths"))
    ).lower()
    values: list[str] = []

    if "mysql" in joined or "mysqli" in joined:
        values.append("MySQL")
    if "postgres" in joined or "pgsql" in joined:
        values.append("PostgreSQL")
    if "sqlite" in joined:
        values.append("SQLite")
    if "mongo" in joined:
        values.append("MongoDB")
    if "redis" in joined:
        values.append("Redis")
    if not values and ("sql" in joined or "migration" in joined or "schema" in joined or "dbservice" in joined):
        values.append("SQL Database")
    return _unique(values)


def _first_named_entity(text: str) -> str:
    patterns = [
        r"\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b",
        r"\b([A-Z][A-Za-z0-9]+(?:Wiki|CMS|ERP|CRM))\b",
        r"([A-Za-z][A-Za-z0-9_-]{2,})\.php",
    ]
    generic = {
        "index",
        "install",
        "config",
        "controller",
        "service",
        "handler",
        "template",
        "command",
        "module",
        "action",
        "router",
        "plugin",
    }

    for pattern in patterns:
        for match in re.finditer(pattern, text):
            candidate = match.group(1).strip("-_ ")
            if candidate.lower() in generic:
                continue
            if candidate.lower() == "yeswiki":
                return "YesWiki"
            return candidate
    return ""


def _ensure_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    cleaned: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            cleaned.append(value.strip())
    return cleaned


def _known_string_list(values: Any) -> list[str]:
    return _unique(
        value
        for value in _ensure_string_list(values)
        if _known_text(value)
    )


def _known_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or text.casefold() == "unknown":
        return ""
    return text


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _join_cn_list(values: list[str]) -> str:
    cleaned = [item for item in values if item]
    return "、".join(cleaned) if cleaned else "unknown"


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _parse_json_object(raw: str) -> dict[str, Any]:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = _strip_code_fence(cleaned)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        parsed = json.loads(_extract_json_object(cleaned))

    if not isinstance(parsed, dict):
        raise ValueError("TreeScan Agent response must be a JSON object.")

    return parsed


def _strip_code_fence(text: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _extract_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError("TreeScan Agent response does not contain a JSON object.")

    return text[start : end + 1]

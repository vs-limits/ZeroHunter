"""Rust — generic File-Path operation sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_path"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-path-fs-create-dir",
        function="fs::create_dir / create_dir_all",
        call_regex=r"\bfs\s*::\s*create_dir(?:_all)?\s*\(",
        description="Creating directory with caller-supplied path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-path-fs-permissions",
        function="fs::set_permissions",
        call_regex=r"\bfs\s*::\s*set_permissions\s*\(",
        description="Changing permissions on caller-controlled path.",
        argument_roles=["path", "perm"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-path-symlink",
        function="std::os::unix::fs::symlink / std::os::windows::fs::symlink_file",
        call_regex=r"\bsymlink(?:_file|_dir)?\s*\(",
        description="symlink creation with attacker-supplied target.",
        argument_roles=["original", "link"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
]

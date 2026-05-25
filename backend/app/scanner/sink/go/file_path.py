"""Go — generic File-Path operation sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_path"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-path-os-stat",
        function="os.Stat / Lstat",
        call_regex=r"\bos\s*\.\s*(?:Stat|Lstat)\s*\(",
        description="Stat with dynamic path — existence side-channel.",
        argument_roles=["name"],
        extensions=_GO,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-os-mkdir",
        function="os.Mkdir / MkdirAll / MkdirTemp",
        call_regex=r"\bos\s*\.\s*(?:Mkdir|MkdirAll|MkdirTemp)\s*\(",
        description="Creating directory with caller-controlled path.",
        argument_roles=["name", "perm"],
        extensions=_GO,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-os-chmod",
        function="os.Chmod / Chown / Lchown",
        call_regex=r"\bos\s*\.\s*(?:Chmod|Chown|Lchown)\s*\(",
        description="Changing permissions of caller-supplied path.",
        argument_roles=["name", "mode"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-os-symlink",
        function="os.Symlink / Link",
        call_regex=r"\bos\s*\.\s*(?:Symlink|Link)\s*\(",
        description="Creating symlink with attacker-supplied target.",
        argument_roles=["oldname", "newname"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

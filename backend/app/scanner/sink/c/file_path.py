"""C — generic File-Path operation sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_path"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-path-chmod",
        function="chmod / fchmod / lchmod",
        call_regex=r"\b(?:chmod|fchmod|lchmod|fchmodat)\s*\(",
        description="Changing permissions of caller-controlled path.",
        argument_roles=["pathname", "mode"],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-path-chown",
        function="chown / fchown / lchown",
        call_regex=r"\b(?:chown|fchown|lchown|fchownat)\s*\(",
        description="Changing ownership — privilege escalation if attacker controls path.",
        argument_roles=["pathname", "owner", "group"],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-path-mktemp",
        function="mktemp / tmpnam / tempnam",
        call_regex=r"\b(?:mktemp|tmpnam|tempnam)\s*\(",
        description="Predictable temp file names — TOCTOU/symlink attacks.",
        argument_roles=["template"],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-path-mkstemp-base",
        function="mkstemp template",
        call_regex=r"\bmkstemp(?:s|64)?\s*\(",
        description="mkstemp template — confirm template doesn't include user input.",
        argument_roles=["template"],
        extensions=_C,
        severity="low",
    ),
    SinkRule(
        id="c-path-mkdir-dynamic",
        function="mkdir / mkdirat",
        call_regex=r"\bmkdir(?:at)?\s*\(",
        description="Creating directory with dynamic path.",
        argument_roles=["pathname", "mode"],
        extensions=_C,
        severity="low",
        require_dynamic=True,
    ),
]

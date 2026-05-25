"""C — Unauthorized Access sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-authz-setuid-suid",
        function="setuid(0) outside privilege boundary",
        call_regex=r"\b(?:setuid|seteuid|setresuid|setgid|setegid)\s*\(\s*0\s*\)",
        description="Elevating to root — review calling context.",
        argument_roles=[],
        extensions=_C,
        severity="high",
    ),
    SinkRule(
        id="c-authz-chmod-world-writable",
        function="chmod(path, 0777)",
        call_regex=r"\bchmod\s*\(\s*[^,]+,\s*0?7(?:7|6|5)\d",
        description="World-writable / world-readable permission constants.",
        argument_roles=["pathname", "mode"],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-authz-umask-loose",
        function="umask(0)",
        call_regex=r"\bumask\s*\(\s*0\s*\)",
        description="umask(0) leaves all permissions exposed.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
    ),
]

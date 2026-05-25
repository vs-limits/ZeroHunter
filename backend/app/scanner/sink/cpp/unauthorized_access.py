"""C++ — Unauthorized Access sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-authz-setuid-zero",
        function="setuid(0) / seteuid(0)",
        call_regex=r"\b(?:setuid|seteuid|setresuid|setgid|setegid)\s*\(\s*0",
        description="Elevation to root privileges.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
    ),
    SinkRule(
        id="cpp-authz-impersonate",
        function="ImpersonateLoggedOnUser / ImpersonateNamedPipeClient",
        call_regex=r"\bImpersonate(?:LoggedOnUser|NamedPipeClient|SelfWithUserCredentials)\s*\(",
        description="Windows impersonation API can drop access controls.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
    ),
    SinkRule(
        id="cpp-authz-cors-wildcard",
        function="add_header Access-Control-Allow-Origin *",
        call_regex=r"Access-Control-Allow-Origin[\"']?\s*[,:]?\s*[\"']?\s*\*",
        description="CORS wildcard origin allowed.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
]

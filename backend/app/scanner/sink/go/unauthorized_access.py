"""Go — Unauthorized Access sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-authz-router-no-mw",
        function="router.GET / POST without auth mw",
        call_regex=r"\.\s*(?:GET|POST|PUT|DELETE|PATCH)\s*\(\s*\"/(?:admin|internal|api)",
        description="Privileged-looking route — verify auth middleware in chain.",
        argument_roles=["path", "handler"],
        extensions=_GO,
        severity="low",
    ),
    SinkRule(
        id="go-authz-cors-allow-creds-wildcard",
        function="AllowCredentials true + wildcard origin",
        call_regex=r"AllowCredentials\s*:\s*true",
        description="CORS allowing credentials — verify origins are restricted.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-authz-pprof-mux",
        function="pprof handlers on default mux",
        call_regex=r"\"net/http/pprof\"",
        description="pprof exposes profiling endpoints on whichever mux uses DefaultServeMux.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
]

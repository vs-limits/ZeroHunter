"""Rust — Unauthorized Access sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-authz-actix-route",
        function="App::new().route(\"/admin\", web::get().to(handler))",
        call_regex=r"\.\s*route\s*\(\s*\"/(?:admin|internal|api)",
        description="Privileged-looking actix route — verify auth middleware in chain.",
        argument_roles=["path", "method_routing"],
        extensions=_RS,
        severity="low",
    ),
    SinkRule(
        id="rs-authz-axum-route-no-mw",
        function="Router::new().route(\"/admin\", ...)",
        call_regex=r"\bRouter\s*::\s*new\s*\(\s*\)\s*\.\s*route\s*\(\s*\"/(?:admin|internal)",
        description="axum router route — verify auth layer present.",
        argument_roles=[],
        extensions=_RS,
        severity="low",
    ),
    SinkRule(
        id="rs-authz-rocket-mount-no-guard",
        function="rocket::routes![] without request guard",
        call_regex=r"\brocket\s*::\s*routes!\s*\[",
        description="rocket routes! macro — verify request guards on each handler.",
        argument_roles=[],
        extensions=_RS,
        severity="low",
    ),
]

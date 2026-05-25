"""Rust — CSRF / CORS sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "csrf"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-csrf-actix-cors-permissive",
        function="Cors::permissive() / allow_any_origin",
        call_regex=r"\bCors\s*::\s*permissive\s*\(\s*\)|\.\s*allow_any_origin\s*\(\s*\)",
        description="actix-cors permissive() or allow_any_origin() opens cross-site requests.",
        argument_roles=[],
        extensions=_RS,
        severity="high",
    ),
    SinkRule(
        id="rs-csrf-tower-cors-any",
        function="tower_http::cors::CorsLayer.allow_origin(Any)",
        call_regex=r"\.\s*allow_origin\s*\(\s*(?:Any|cors::Any)",
        description="tower_http CORS allow_origin(Any).",
        argument_roles=[],
        extensions=_RS,
        severity="high",
    ),
    SinkRule(
        id="rs-csrf-samesite-none",
        function="Cookie SameSite::None",
        call_regex=r"SameSite\s*::\s*None",
        description="Cookie SameSite=None makes it cross-site sendable.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
]

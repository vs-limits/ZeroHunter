"""Rust — CRLF / Header Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "crlf_injection"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-crlf-header-insert",
        function="HeaderMap.insert / append",
        call_regex=r"\.\s*(?:insert|append)\s*\(\s*(?:header::|HeaderName::|\"[A-Za-z\-]+\")",
        description="HeaderMap insert/append with dynamic value.",
        argument_roles=["key", "value"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-crlf-actix-cookie",
        function="HttpResponse::Ok().cookie(Cookie::new(...))",
        call_regex=r"\bCookie\s*::\s*new\s*\(",
        description="Constructing cookie with dynamic name/value.",
        argument_roles=["name", "value"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-crlf-redirect",
        function="HttpResponse::Found().append_header((LOCATION, url))",
        call_regex=r"LOCATION\s*,\s*[a-zA-Z_]",
        description="Redirect Location header from dynamic value.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
]

"""Go — CRLF / Header Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "crlf_injection"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-crlf-w-header-set",
        function="w.Header().Set / Add",
        call_regex=r"\.\s*Header\s*\(\s*\)\s*\.\s*(?:Set|Add)\s*\(",
        description="Setting response header value built from user input.",
        argument_roles=["key", "value"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-crlf-redirect",
        function="http.Redirect",
        call_regex=r"\bhttp\s*\.\s*Redirect\s*\(",
        description="http.Redirect with user-controlled URL.",
        argument_roles=["w", "r", "url", "code"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-crlf-setcookie",
        function="http.SetCookie(w, cookie)",
        call_regex=r"\bhttp\s*\.\s*SetCookie\s*\(",
        description="Cookie value built from user input.",
        argument_roles=["w", "cookie"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-crlf-gin-redirect",
        function="c.Redirect",
        call_regex=r"\bc\s*\.\s*Redirect\s*\(",
        description="Gin Redirect with dynamic URL.",
        argument_roles=["code", "location"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

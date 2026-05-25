"""JavaScript / Node.js — CRLF / Header Injection sinks (CWE-93, CWE-113)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "crlf_injection"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-crlf-res-setheader",
        function="res.setHeader / res.header",
        call_regex=r"\bres\s*\.\s*(?:setHeader|header|append|writeHead)\s*\(",
        description="Setting response header value built from user input.",
        argument_roles=["name", "value"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-crlf-res-redirect",
        function="res.redirect(url)",
        call_regex=r"\bres\s*\.\s*redirect\s*\(",
        description="Open redirect + CRLF when destination is user-controlled.",
        argument_roles=["url"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-crlf-res-cookie",
        function="res.cookie(name, value)",
        call_regex=r"\bres\s*\.\s*cookie\s*\(",
        description="Setting cookie with attacker-controlled name or value.",
        argument_roles=["name", "value", "options"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-crlf-koa-set",
        function="ctx.set / ctx.append",
        call_regex=r"\bctx\s*\.\s*(?:set|append)\s*\(",
        description="Koa response header setter — verify value sanitisation.",
        argument_roles=["field", "val"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-crlf-nestjs-set-header",
        function="@Header decorator + dynamic Header()",
        call_regex=r"@Header\s*\(",
        description="Nest @Header set with non-literal value — verify sanitisation.",
        argument_roles=["name", "value"],
        extensions=_JS,
        severity="low",
    ),
]

"""HTML — Misconfiguration flags around access control (CORS / CSP meta)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_HTML = [".html", ".htm", ".xhtml"]

RULES = [
    SinkRule(
        id="html-authz-csp-unsafe-inline",
        function="<meta http-equiv=\"Content-Security-Policy\" content=\"...'unsafe-inline'...\">",
        call_regex=r"unsafe-inline|unsafe-eval",
        description="CSP allowing 'unsafe-inline' / 'unsafe-eval' defeats most XSS protection.",
        argument_roles=[],
        extensions=_HTML,
        severity="high",
    ),
    SinkRule(
        id="html-authz-csp-wildcard",
        function="CSP wildcard source",
        call_regex=r"Content-Security-Policy[\"']?\s*content\s*=\s*[\"'][^\"']*\*",
        description="CSP using * weakens protection.",
        argument_roles=[],
        extensions=_HTML,
        severity="medium",
    ),
    SinkRule(
        id="html-authz-cors-allow-all",
        function="<meta http-equiv=\"Access-Control-Allow-Origin\" content=\"*\">",
        call_regex=r"Access-Control-Allow-Origin[\"']?\s*content\s*=\s*[\"']\s*\*",
        description="Meta-level CORS wildcard.",
        argument_roles=[],
        extensions=_HTML,
        severity="medium",
    ),
]

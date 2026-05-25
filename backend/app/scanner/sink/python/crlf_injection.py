"""Python — CRLF / Header Injection sinks (CWE-93, CWE-113)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "crlf_injection"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-crlf-flask-headers",
        function="response.headers.add / set",
        call_regex=r"\.\s*headers\s*\.\s*(?:add|set|setdefault|__setitem__)\s*\(",
        description="Setting response header value from dynamic source — CRLF risk.",
        argument_roles=["name", "value"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-crlf-make-response-header",
        function="response.headers[...] = ...",
        call_regex=r"\.\s*headers\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*=",
        description="Direct dict-style header assignment.",
        argument_roles=["value"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-crlf-redirect",
        function="redirect / url_for",
        call_regex=r"\b(?:redirect|url_for)\s*\(",
        description="Open redirect / Location header injection when target is user-controlled.",
        argument_roles=["location"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-crlf-django-httpresponse-header",
        function="HttpResponse[hdr] = value",
        call_regex=r"\bHttpResponse(?:Redirect)?\s*\([^)]*\)\s*\[\s*['\"]",
        description="Django HttpResponse header set with dynamic value.",
        argument_roles=["header", "value"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-crlf-wsgi-start-response",
        function="start_response",
        call_regex=r"\bstart_response\s*\(",
        description="WSGI start_response building response header list dynamically.",
        argument_roles=["status", "headers"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-crlf-smtplib-sendmail",
        function="smtplib.SMTP.sendmail",
        call_regex=r"\.\s*sendmail\s*\(",
        description="SMTP header injection through 2nd/3rd args containing CRLF.",
        argument_roles=["from_addr", "to_addrs", "msg"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
]

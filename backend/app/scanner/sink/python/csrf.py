"""Python — CSRF sinks (CWE-352).

We detect places that *disable* CSRF protection rather than execute it.
"""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "csrf"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-csrf-django-exempt",
        function="@csrf_exempt",
        call_regex=r"@\s*csrf_exempt\b",
        description="Django @csrf_exempt decorator disables CSRF token check for a view.",
        argument_roles=[],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-csrf-flask-wtf-disable",
        function="WTF_CSRF_ENABLED = False",
        call_regex=r"\bWTF_CSRF_ENABLED\s*=\s*False",
        description="Flask-WTF CSRF protection turned off globally.",
        argument_roles=[],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-csrf-flask-wtf-omit",
        function="CSRFProtect not initialised",
        call_regex=r"\bCSRFProtect\s*\(",
        description="Track Flask-WTF CSRFProtect to ensure it is initialised on app.",
        argument_roles=["app"],
        extensions=_PY,
        severity="low",
    ),
    SinkRule(
        id="py-csrf-django-mw-removed",
        function="CsrfViewMiddleware removed",
        call_regex=r"['\"]django\.middleware\.csrf\.CsrfViewMiddleware['\"]",
        description="Track CsrfViewMiddleware presence in MIDDLEWARE list.",
        argument_roles=[],
        extensions=_PY,
        severity="low",
    ),
    SinkRule(
        id="py-csrf-fastapi-no-token",
        function="FastAPI form POST without CSRF",
        call_regex=r"@\s*app\.\s*(?:post|put|delete)\s*\(",
        description="FastAPI state-changing route — verify CSRF/SameSite cookie strategy.",
        argument_roles=["path"],
        extensions=_PY,
        severity="low",
    ),
    SinkRule(
        id="py-csrf-tornado-disable",
        function="check_xsrf_cookie override",
        call_regex=r"def\s+check_xsrf_cookie\s*\(",
        description="Tornado handler overriding check_xsrf_cookie to bypass XSRF check.",
        argument_roles=[],
        extensions=_PY,
        severity="high",
    ),
]

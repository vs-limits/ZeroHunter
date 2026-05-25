"""Python — Unauthorized / Missing Access Control sinks (CWE-862, CWE-863)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-authz-drf-allow-any",
        function="DRF permission_classes=[AllowAny]",
        call_regex=r"permission_classes\s*=\s*\[?\s*AllowAny",
        description="Django REST view explicitly allows anonymous access.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-authz-drf-default-permission",
        function="DEFAULT_PERMISSION_CLASSES = AllowAny",
        call_regex=r"DEFAULT_PERMISSION_CLASSES['\"]?\s*:\s*[\(\[][^)\]]*AllowAny",
        description="Project-wide default permission set to AllowAny.",
        argument_roles=[],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-authz-fastapi-no-dependency",
        function="FastAPI route without auth dependency",
        call_regex=r"@\s*(?:app|router)\.\s*(?:get|post|put|delete|patch)\s*\(",
        description="FastAPI route — verify Depends(get_current_user) etc. is present.",
        argument_roles=["path"],
        extensions=_PY,
        severity="low",
    ),
    SinkRule(
        id="py-authz-flask-route-no-decorator",
        function="@app.route without @login_required",
        call_regex=r"@\s*app\.\s*route\s*\(",
        description="Flask route — manually verify @login_required / before_request guards.",
        argument_roles=["rule"],
        extensions=_PY,
        severity="low",
    ),
    SinkRule(
        id="py-authz-django-superuser-check",
        function="user.is_superuser direct compare",
        call_regex=r"\.\s*is_superuser\s*==",
        description="is_superuser checked instead of permission framework.",
        argument_roles=[],
        extensions=_PY,
        severity="low",
    ),
    SinkRule(
        id="py-authz-cors-allow-any",
        function="CORS allow-all origins",
        call_regex=r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[?\s*['\"]\*['\"]",
        description="CORS configured to accept any origin.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-authz-debug-endpoints",
        function="debug/admin endpoint route",
        call_regex=r"@\s*(?:app|router)\.\s*(?:get|post)\s*\(\s*['\"]/(?:debug|admin|internal)",
        description="Possible internal endpoint exposed; confirm auth.",
        argument_roles=["path"],
        extensions=_PY,
        severity="medium",
    ),
]

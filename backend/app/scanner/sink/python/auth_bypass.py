"""Python — Authentication Bypass sinks (CWE-287, CWE-305)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-auth-jwt-decode-noverify",
        function="jwt.decode(verify=False)",
        call_regex=r"\bjwt\.\s*decode\s*\(",
        description="PyJWT decode without signature verification or with options={'verify_signature': False}.",
        argument_roles=["jwt", "key", "options"],
        extensions=_PY,
        severity="critical",
        extra_match_regex=[
            r"verify\s*=\s*False",
            r"verify_signature['\"]?\s*:\s*False",
            r"algorithms\s*=\s*None",
        ],
    ),
    SinkRule(
        id="py-auth-jwt-alg-none",
        function="jwt.encode/decode algorithm=none",
        call_regex=r"algorithms?\s*=\s*\[?\s*['\"]none['\"]",
        description="JWT alg='none' disables signature verification entirely.",
        argument_roles=["alg"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-auth-password-equality",
        function="naive password equality (==)",
        call_regex=r"\b(?:password|pwd|passwd|secret|token)\s*==",
        description="Comparing passwords/tokens with == leaks timing; use hmac.compare_digest.",
        argument_roles=["a", "b"],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-auth-hashlib-md5-sha1",
        function="hashlib.md5 / sha1 for password",
        call_regex=r"\bhashlib\.\s*(?:md5|sha1)\s*\(",
        description="MD5/SHA1 used (often for password hashing); broken / fast — switch to bcrypt/argon2.",
        argument_roles=["data"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-auth-django-login-required-missing",
        function="@login_required absent",
        call_regex=r"@\s*csrf_exempt\b[\s\S]*?def\s+",
        description="csrf_exempt view without @login_required nearby — review auth gating.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-auth-flask-login-disable",
        function="LOGIN_DISABLED = True",
        call_regex=r"\bLOGIN_DISABLED\s*=\s*True",
        description="Flask-Login global bypass switch left on.",
        argument_roles=[],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-auth-debug-toolbar",
        function="DEBUG = True in production config",
        call_regex=r"\bDEBUG\s*=\s*True",
        description="Django/Flask DEBUG=True leaks tracebacks and may unlock admin paths.",
        argument_roles=[],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-auth-session-secret-hardcoded",
        function="SECRET_KEY / SESSION_KEY hardcoded",
        call_regex=r"\b(?:SECRET_KEY|SESSION_KEY)\s*=\s*['\"][^'\"]+['\"]",
        description="Hardcoded session signing key.",
        argument_roles=[],
        extensions=_PY,
        severity="high",
    ),
]

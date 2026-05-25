"""Go — CSRF / CORS sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "csrf"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-csrf-gorilla-csrf-skip",
        function="csrf.Protect with TrustedOrigins permissive",
        call_regex=r"\bcsrf\s*\.\s*Protect\s*\(",
        description="gorilla/csrf middleware mounted — verify TrustedOrigins / Secure.",
        argument_roles=[],
        extensions=_GO,
        severity="low",
    ),
    SinkRule(
        id="go-csrf-gin-cors-any",
        function="cors.Default / AllowAllOrigins:true",
        call_regex=r"\bcors\s*\.\s*Default\s*\(\s*\)|AllowAllOrigins\s*:\s*true",
        description="CORS allow-all-origins, especially with AllowCredentials:true, breaks CSRF protection.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-csrf-cookie-samesite-none",
        function="cookie.SameSite = SameSiteNoneMode",
        call_regex=r"SameSite\s*=\s*[a-zA-Z]*None",
        description="SameSite=None cookie is cross-site-sendable.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
]

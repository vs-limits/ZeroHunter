"""JavaScript / Node.js — CSRF sinks (CWE-352)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "csrf"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-csrf-csurf-missing",
        function="csurf middleware not mounted",
        call_regex=r"\bapp\.\s*use\s*\(\s*csurf",
        description="Track csurf middleware mounting — its absence is the actual issue.",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-csrf-cors-credentials-wildcard",
        function="cors({origin:'*', credentials:true})",
        call_regex=r"\bcors\s*\(\s*\{[^}]*credentials\s*:\s*true",
        description="CORS allowing credentials with wildcard / dynamic origin function.",
        argument_roles=["options"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-csrf-fastify-disable",
        function="fastify-csrf disabled",
        call_regex=r"@fastify/csrf[^\n]*\bdisable",
        description="Explicit disable of fastify CSRF plugin.",
        argument_roles=[],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-csrf-samesite-none",
        function="cookie sameSite:'none' without secure",
        call_regex=r"sameSite\s*:\s*['\"]none['\"]",
        description="sameSite=none cookie eligible for cross-site sending.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-csrf-state-changing-get",
        function="state-changing GET handler",
        call_regex=r"\bapp\s*\.\s*get\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:async\s*)?\(",
        description="GET handler — verify it does not mutate state (CSRF-friendly).",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
]

"""JavaScript / Node.js — Unauthorized / Missing Access Control sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-authz-express-no-mw",
        function="app.get/post route without middleware",
        call_regex=r"\bapp\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['\"]/(?:admin|api|internal)",
        description="Privileged-looking route — verify auth middleware in chain.",
        argument_roles=["path", "handler"],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-authz-nestjs-public",
        function="@Public() decorator",
        call_regex=r"@Public\s*\(\s*\)",
        description="NestJS @Public() bypasses Guard auth.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-authz-nextjs-api-no-getserversideprops",
        function="Next.js API route without auth check",
        call_regex=r"\bexport\s+default\s+(?:async\s+)?function\s+handler",
        description="Next.js API handler — verify session/role check.",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-authz-cors-any-origin",
        function="cors({origin:true})",
        call_regex=r"\bcors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|['\"]\*['\"])",
        description="CORS reflecting/wildcarding origin.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-authz-graphql-no-context-auth",
        function="GraphQL resolver without context auth",
        call_regex=r"resolve\s*:\s*(?:async\s*)?\(\s*(?:parent|root)\s*,",
        description="GraphQL resolver — verify ctx.user/role check.",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
]

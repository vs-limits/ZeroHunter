"""JavaScript / Node.js — Information Disclosure sinks (CWE-200)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-info-stack-trace-response",
        function="res.send(err.stack)",
        call_regex=r"\.\s*send\s*\(\s*[^)]*\.\s*stack",
        description="Sending error.stack to client leaks file paths.",
        argument_roles=["body"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-info-console-secret",
        function="console.log(secret)",
        call_regex=r"\bconsole\s*\.\s*(?:log|info|debug|warn|error)\s*\([^)]*(?:password|secret|token|api[_-]?key)",
        description="console logging of secret-named variable.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-info-error-listener-print",
        function="process.on('uncaughtException') logging",
        call_regex=r"process\s*\.\s*on\s*\(\s*['\"](?:uncaughtException|unhandledRejection)['\"]",
        description="Unhandled error handler — confirm it doesn't dump to a client response.",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-info-express-xpoweredby",
        function="Express x-powered-by default header",
        call_regex=r"\bapp\.\s*disable\s*\(\s*['\"]x-powered-by['\"]",
        description="Track whether x-powered-by is disabled (its absence leaks 'Express').",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-info-env-dump",
        function="JSON.stringify(process.env)",
        call_regex=r"\bJSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env",
        description="Stringifying process.env into response leaks secrets.",
        argument_roles=[],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-info-source-map-prod",
        function="source-map-support enabled in prod",
        call_regex=r"\brequire\s*\(\s*['\"]source-map-support['\"]\s*\)\s*\.\s*install\s*\(",
        description="source-map-support exposes original source paths in tracebacks.",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
]

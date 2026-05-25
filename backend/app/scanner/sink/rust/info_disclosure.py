"""Rust — Information Disclosure sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-info-dbg-macro",
        function="dbg!(secret)",
        call_regex=r"\bdbg!\s*\([^)]*(?:password|secret|token|api[_-]?key)",
        description="dbg!() of credential-named binding prints to stderr.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-info-println-secret",
        function="println!/eprintln! of secret",
        call_regex=r"\b(?:println|eprintln|print|eprint|tracing::info|tracing::debug|tracing::error)\s*\(\s*\"[^\"]*\{\?\}\s*\",\s*\w*(?:password|secret|token|api[_-]?key)",
        description="Logging credential-named field.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-info-anyhow-bail-context",
        function="anyhow!/context with sensitive value",
        call_regex=r"\bcontext\s*\(\s*\"[^\"]*(?:password|secret|token|api[_-]?key)",
        description="anyhow context message including credential.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-info-actix-error-response-debug",
        function="ResponseError using Debug impl",
        call_regex=r"impl\s+ResponseError\s+for\s+\w+",
        description="ResponseError impl — verify error_response() doesn't leak internals.",
        argument_roles=[],
        extensions=_RS,
        severity="low",
    ),
]

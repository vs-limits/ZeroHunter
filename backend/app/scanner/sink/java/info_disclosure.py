"""Java — Information Disclosure sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-info-exception-printstack",
        function="Throwable.printStackTrace()",
        call_regex=r"\.\s*printStackTrace\s*\(\s*[^)]*\)",
        description="printStackTrace to default System.err or response.getWriter leaks paths.",
        argument_roles=["s"],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-info-spring-error-include",
        function="server.error.include-stacktrace=ALWAYS",
        call_regex=r"include-stacktrace\s*=\s*ALWAYS|include-message\s*=\s*ALWAYS",
        description="Spring Boot error response exposes stack trace.",
        argument_roles=[],
        extensions=[".properties", ".yml", ".yaml"],
        severity="medium",
    ),
    SinkRule(
        id="java-info-actuator-env",
        function="actuator/env exposed",
        call_regex=r"endpoints\.env\.enabled\s*=\s*true|endpoints\.web\.exposure\.include\s*=\s*[^#\n]*\benv\b",
        description="Actuator /env exposes config including secrets.",
        argument_roles=[],
        extensions=[".properties", ".yml", ".yaml"],
        severity="high",
    ),
    SinkRule(
        id="java-info-system-getenv-response",
        function="System.getenv → response",
        call_regex=r"System\s*\.\s*getenv\s*\(\s*\)",
        description="Dumping env into response leaks secrets.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-info-log-secret",
        function="logger.info containing password/token",
        call_regex=r"\blog(?:ger)?\s*\.\s*(?:trace|debug|info|warn|error)\s*\([^)]*(?:password|secret|api[_-]?key|token)",
        description="Logging variables named like credentials.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
]

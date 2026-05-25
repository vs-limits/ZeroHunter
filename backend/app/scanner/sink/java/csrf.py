"""Java — CSRF sinks (CWE-352)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "csrf"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-csrf-spring-security-disable",
        function="http.csrf().disable()",
        call_regex=r"\.\s*csrf\s*\(\s*\)\s*\.\s*disable\s*\(",
        description="Spring Security CSRF protection explicitly disabled.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-csrf-spring-security-ignore",
        function=".csrf().ignoringAntMatchers / ignoringRequestMatchers",
        call_regex=r"\.\s*csrf\s*\(\s*\)\s*[\s\S]{0,80}\.\s*ignoring(?:AntMatchers|RequestMatchers)\s*\(",
        description="Antechamber for CSRF — verify ignored routes don't mutate state.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-csrf-corsconfiguration-wildcard",
        function="CorsConfiguration.addAllowedOrigin('*') + addAllowedMethod('*')",
        call_regex=r"\.\s*addAllowedOrigin\s*\(\s*\"\*\"\s*\)",
        description="CORS allow-any-origin.",
        argument_roles=["origin"],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-csrf-cookie-samesite-none",
        function="Cookie SameSite=None",
        call_regex=r"SameSite\s*=\s*None",
        description="Cookie SameSite=None is cross-site sendable.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
]

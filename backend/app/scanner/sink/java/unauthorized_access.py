"""Java — Unauthorized / Missing Access Control sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-authz-spring-no-preauthorize",
        function="@RequestMapping without @PreAuthorize",
        call_regex=r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(",
        description="Spring mapping — verify @PreAuthorize / @Secured nearby.",
        argument_roles=[],
        extensions=_JAVA,
        severity="low",
    ),
    SinkRule(
        id="java-authz-anyrequest-permitall",
        function=".anyRequest().permitAll()",
        call_regex=r"\.\s*anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(",
        description="Spring Security: every request permitted.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-authz-actuator-all-exposed",
        function="management.endpoints.web.exposure.include=*",
        call_regex=r"endpoints\.web\.exposure\.include\s*=\s*\*",
        description="All Spring Actuator endpoints exposed.",
        argument_roles=[],
        extensions=_JAVA + [".properties", ".yml", ".yaml"],
        severity="critical",
    ),
    SinkRule(
        id="java-authz-jaxrs-rolesallowed-empty",
        function="@RolesAllowed({}) on resource",
        call_regex=r"@RolesAllowed\s*\(\s*\{\s*\}\s*\)",
        description="Empty @RolesAllowed allows nothing — likely typo / disabled gate.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-authz-keycloak-anonymous",
        function="@PermitAll on REST endpoint",
        call_regex=r"@PermitAll\b",
        description="@PermitAll explicitly opens endpoint.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
]

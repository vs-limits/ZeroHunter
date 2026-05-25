"""Java — LDAP Injection sinks (CWE-90)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ldap_injection"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-ldap-dircontext-search",
        function="DirContext.search(base, filter, ...)",
        call_regex=r"\.\s*search\s*\(",
        description="javax.naming.DirContext.search with formatted filter.",
        argument_roles=["base", "filter", "controls"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ldap-initialdircontext-bind",
        function="new InitialDirContext(env).addToEnvironment(SECURITY_PRINCIPAL=...)",
        call_regex=r"SECURITY_PRINCIPAL",
        description="Authentication DN built from user input — DN injection.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ldap-spring-ldaptemplate",
        function="LdapTemplate.search(base, filter, ...)",
        call_regex=r"\bLdapTemplate\b[\s\S]{0,80}\.\s*search\s*\(",
        description="Spring LdapTemplate.search with formatted filter.",
        argument_roles=["base", "filter", "controls", "handler"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ldap-unboundid-search",
        function="LDAPConnection.search(SearchRequest)",
        call_regex=r"\bLDAPConnection\b[\s\S]{0,80}\.\s*search\s*\(",
        description="UnboundID LDAP search with concatenated filter.",
        argument_roles=["request"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
]

"""C — LDAP Injection sinks (openldap / winldap)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ldap_injection"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-ldap-search-ext-s",
        function="ldap_search_ext_s / ldap_search_s",
        call_regex=r"\bldap_search(?:_(?:s|ext|ext_s))?\s*\(",
        description="openldap search with caller-controlled filter.",
        argument_roles=["ld", "base", "scope", "filter"],
        extensions=_C,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-ldap-simple-bind",
        function="ldap_simple_bind_s",
        call_regex=r"\bldap_simple_bind(?:_s)?\s*\(",
        description="Bind DN built from user input.",
        argument_roles=["ld", "who", "passwd"],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
]

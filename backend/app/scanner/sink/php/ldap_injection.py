"""PHP — LDAP Injection sinks (CWE-90)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ldap_injection"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-ldap-search-dynamic",
        function="ldap_search / ldap_list / ldap_read",
        call_regex=r"\bldap_(?:search|list|read)\s*\(",
        description="LDAP search/list/read with a dynamically built filter is vulnerable to LDAP injection.",
        argument_roles=["link", "base_dn", "filter"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-ldap-bind-dynamic",
        function="ldap_bind",
        call_regex=r"\bldap_bind\s*\(",
        description="ldap_bind with user-controlled DN/password is a typical login-bypass.",
        argument_roles=["link", "bind_rdn", "bind_password"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
]

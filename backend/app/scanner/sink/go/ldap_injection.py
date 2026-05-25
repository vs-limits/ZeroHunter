"""Go — LDAP Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ldap_injection"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-ldap-conn-search",
        function="ldap.Conn.Search(searchRequest)",
        call_regex=r"\.\s*Search(?:WithPaging)?\s*\(",
        description="go-ldap Search with concatenated filter.",
        argument_roles=["searchRequest"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ldap-newsearchrequest",
        function="ldap.NewSearchRequest with fmt.Sprintf filter",
        call_regex=r"\bldap\s*\.\s*NewSearchRequest\s*\(",
        description="NewSearchRequest filter built via fmt.Sprintf.",
        argument_roles=["baseDN", "scope", "...filter..."],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ldap-bind-dynamic",
        function="conn.Bind(dn, password) with dynamic dn",
        call_regex=r"\.\s*Bind\s*\(",
        description="go-ldap Bind DN built from user input.",
        argument_roles=["username", "password"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

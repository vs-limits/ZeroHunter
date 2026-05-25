"""C++ — LDAP Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ldap_injection"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-ldap-search",
        function="ldap_search_ext_s / ldap_search_s",
        call_regex=r"\bldap_search(?:_(?:s|ext|ext_s))?\s*\(",
        description="LDAP search with caller-controlled filter from C++.",
        argument_roles=["ld", "base", "scope", "filter"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-ldap-bind",
        function="ldap_simple_bind_s",
        call_regex=r"\bldap_simple_bind(?:_s)?\s*\(",
        description="LDAP bind DN built from user input.",
        argument_roles=["ld", "who", "passwd"],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
]

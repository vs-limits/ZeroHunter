"""Python — LDAP Injection sinks (CWE-90)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ldap_injection"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-ldap-search-s",
        function="ldap.search_s / search_ext_s",
        call_regex=r"\.\s*search(?:_(?:s|ext|ext_s|st))?\s*\(",
        description="python-ldap search with formatted filter is injectable.",
        argument_roles=["base", "scope", "filterstr"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ldap3-search",
        function="ldap3.Connection.search",
        call_regex=r"\.\s*search\s*\(\s*search_filter\s*=",
        description="ldap3 Connection.search with concatenated search_filter.",
        argument_roles=["search_base", "search_filter"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ldap-bind",
        function="ldap.simple_bind_s",
        call_regex=r"\.\s*simple_bind(?:_s)?\s*\(",
        description="Bind DN constructed via string concat may allow filter override.",
        argument_roles=["who", "cred"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
]

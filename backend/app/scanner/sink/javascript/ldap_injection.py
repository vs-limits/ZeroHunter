"""JavaScript / Node.js — LDAP Injection sinks (CWE-90)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ldap_injection"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-ldap-ldapjs-search",
        function="ldapjs client.search(base, opts)",
        call_regex=r"\.\s*search\s*\(\s*[`'\"][^`'\"]*[`'\"]\s*,\s*\{[^}]*filter",
        description="ldapjs search filter built from template literal / concat.",
        argument_roles=["base", "options"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-ldap-activedirectory-find",
        function="activedirectory.find / findUser",
        call_regex=r"\bactiveDirectory\s*\.\s*(?:find|findUser|findGroup)\s*\(",
        description="activedirectory query with user-controlled filter.",
        argument_roles=["query", "callback"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-ldap-bind-dn-concat",
        function="bind DN built via concatenation",
        call_regex=r"\bclient\s*\.\s*bind\s*\(",
        description="ldapjs bind DN from concatenated user input — DN injection.",
        argument_roles=["dn", "password"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
]

"""PHP — XPath Injection sinks (CWE-643)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xpath_injection"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-xpath-domxpath-query",
        function="DOMXPath::query / evaluate",
        # Gate with DOMXPath context — otherwise `->query(` collides with PDO,
        # Doctrine QueryBuilder, etc. on the same line.
        call_regex=r"->\s*(?:query|evaluate)\s*\(",
        description="DOMXPath::query/evaluate runs a (potentially user-controlled) XPath expression.",
        argument_roles=["xpath", "context"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"DOMXPath", r"DOMDocument", r"\$xpath\b"],
    ),
    SinkRule(
        id="php-xpath-simplexml-xpath",
        function="SimpleXMLElement::xpath",
        call_regex=r"->\s*xpath\s*\(",
        description="SimpleXMLElement::xpath with a variable expression.",
        argument_roles=["xpath"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
]

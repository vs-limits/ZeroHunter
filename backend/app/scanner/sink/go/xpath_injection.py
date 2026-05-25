"""Go — XPath Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xpath_injection"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-xpath-xmlquery-find",
        function="xmlquery.Find / FindOne / Select",
        call_regex=r"\bxmlquery\s*\.\s*(?:Find|FindOne|FindEach|Select|QueryAll)\s*\(",
        description="antchfx/xmlquery XPath query with concatenated expression.",
        argument_roles=["top", "expr"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-xpath-htmlquery-find",
        function="htmlquery.Find / Select",
        call_regex=r"\bhtmlquery\s*\.\s*(?:Find|FindOne|Select|QueryAll)\s*\(",
        description="antchfx/htmlquery XPath query — same concern.",
        argument_roles=["top", "expr"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

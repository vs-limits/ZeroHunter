"""Python — XPath Injection sinks (CWE-643)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xpath_injection"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-xpath-lxml-xpath",
        function="Element.xpath",
        call_regex=r"\.\s*xpath\s*\(",
        description="lxml/ElementTree xpath() with formatted/concatenated query.",
        argument_roles=["expression"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-xpath-etree-find",
        function="Element.find / findall / findtext",
        call_regex=r"\.\s*(?:find|findall|findtext|iterfind)\s*\(",
        description="ElementTree find* with concatenated XPath expression.",
        argument_roles=["match"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-xpath-defusedxml-xpath",
        function="defusedxml.etree.xpath",
        call_regex=r"\bdefusedxml[^\s]*\.\s*xpath\s*\(",
        description="defusedxml is XXE-safe but XPath query content is still user-controlled.",
        argument_roles=["expression"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
]

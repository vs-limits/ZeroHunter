"""Java — XPath Injection sinks (CWE-643)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xpath_injection"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-xpath-xpath-evaluate",
        function="XPath.evaluate / compile",
        call_regex=r"\bxpath\s*\.\s*(?:evaluate|compile)\s*\(",
        description="javax.xml.xpath.XPath.evaluate with concatenated expression.",
        argument_roles=["expression", "item"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-xpath-jdom-getxpath",
        function="JDOM XPath.newInstance",
        call_regex=r"\bXPath\s*\.\s*newInstance\s*\(",
        description="JDOM XPath built from concatenated string.",
        argument_roles=["expression"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-xpath-dom4j-selectNodes",
        function="Element.selectNodes / selectSingleNode",
        call_regex=r"\.\s*select(?:Nodes|SingleNode|Object)\s*\(",
        description="dom4j Element.select* methods with dynamic XPath.",
        argument_roles=["expression"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
]

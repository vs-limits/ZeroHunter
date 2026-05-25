"""C++ — XPath Injection sinks (libxml2 XPath, Xerces)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xpath_injection"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-xpath-libxml-eval",
        function="xmlXPathEvalExpression",
        call_regex=r"\bxmlXPath(?:Eval|EvalExpression|Compile|NewContext)\s*\(",
        description="libxml2 XPath eval with concatenated expression.",
        argument_roles=["str", "ctxt"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-xpath-xerces-evaluate",
        function="DOMXPathExpression::evaluate",
        call_regex=r"\bDOMXPath(?:Expression|Result)\b[\s\S]{0,40}\.\s*evaluate\s*\(",
        description="Xerces-C XPath evaluate with dynamic expression.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-xpath-pugixml-select",
        function="pugixml node.select_node / select_nodes",
        call_regex=r"\.\s*select_(?:node|nodes|single_node)\s*\(",
        description="pugixml XPath query built from user input.",
        argument_roles=["query"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
]

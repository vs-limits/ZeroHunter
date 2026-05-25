"""JavaScript / Node.js — XPath Injection sinks (CWE-643)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xpath_injection"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-xpath-xpath-select",
        function="xpath.select(expr, doc)",
        call_regex=r"\bxpath\s*\.\s*select(?:1)?\s*\(",
        description="xpath.select with concatenated/templated XPath expression.",
        argument_roles=["expression", "node"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-xpath-document-evaluate",
        function="document.evaluate(expr, ...)",
        call_regex=r"\.\s*evaluate\s*\(\s*[a-zA-Z_`]",
        description="DOM document.evaluate with dynamic expression.",
        argument_roles=["xpathExpression"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-xpath-libxmljs-find",
        function="libxmljs Element.find / get",
        call_regex=r"\.\s*(?:find|get)\s*\(\s*`[^`]*\$\{",
        description="libxmljs find/get with template-literal XPath.",
        argument_roles=["expression"],
        extensions=_JS,
        severity="high",
    ),
]

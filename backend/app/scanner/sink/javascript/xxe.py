"""JavaScript / Node.js — XXE sinks (CWE-611)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xxe"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-xxe-xml2js-parsestring",
        function="xml2js parseString / parser.parseString",
        call_regex=r"\.\s*parseString\s*\(",
        description="xml2js parser by default disables entity expansion, but custom options may re-enable.",
        argument_roles=["xml", "callback"],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-xxe-libxmljs-parsexml",
        function="libxmljs.parseXml / parseXmlString",
        call_regex=r"\blibxmljs\s*\.\s*parseXml(?:String)?\s*\(",
        description="libxmljs parse with noent/dtdload options is XXE-vulnerable.",
        argument_roles=["xml", "options"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-xxe-xmldom-domparser",
        function="new DOMParser().parseFromString",
        call_regex=r"\bDOMParser\s*\(\s*\)\s*\.\s*parseFromString\s*\(",
        description="xmldom DOMParser; older versions allow external entity references.",
        argument_roles=["xml", "type"],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-xxe-fast-xml-parser",
        function="fast-xml-parser parse",
        call_regex=r"\bXMLParser\s*\(\s*\)\.\s*parse\s*\(",
        description="fast-xml-parser parse — confirm processEntities/allowBooleanAttributes settings.",
        argument_roles=["xml"],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-xxe-sax-parser-strict",
        function="sax.parser(strict, opts)",
        call_regex=r"\bsax\s*\.\s*parser\s*\(",
        description="sax SAX parser with non-strict mode.",
        argument_roles=["strict", "opts"],
        extensions=_JS,
        severity="medium",
    ),
]

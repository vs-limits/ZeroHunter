"""C — XXE sinks (libxml2, expat)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xxe"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-xxe-libxml-parsefile",
        function="xmlReadFile / xmlReadMemory / xmlReadIO",
        call_regex=r"\bxmlRead(?:File|Memory|IO|Doc)\s*\(",
        description="libxml2 parsing without XML_PARSE_NOENT|NONET flags is XXE-vulnerable.",
        argument_roles=["url", "encoding", "options"],
        extensions=_C,
        severity="high",
    ),
    SinkRule(
        id="c-xxe-libxml-ctxt",
        function="xmlCtxtReadFile / Memory",
        call_regex=r"\bxmlCtxtRead(?:File|Memory|IO|Doc)\s*\(",
        description="libxml2 Ctxt read variants with default options.",
        argument_roles=["ctxt", "input", "url", "encoding", "options"],
        extensions=_C,
        severity="high",
    ),
    SinkRule(
        id="c-xxe-libxml-parsefile-legacy",
        function="xmlParseFile / xmlParseDoc",
        call_regex=r"\bxml(?:Parse|SAXParse)(?:File|Doc|Memory)\s*\(",
        description="Legacy libxml2 parse API — entity processing on by default.",
        argument_roles=["filename"],
        extensions=_C,
        severity="high",
    ),
    SinkRule(
        id="c-xxe-expat-parse",
        function="XML_Parse / XML_ParseBuffer",
        call_regex=r"\bXML_Parse(?:Buffer)?\s*\(",
        description="expat parses entities unless XML_SetEntityDeclHandler / etc are set.",
        argument_roles=["parser", "s", "len", "isFinal"],
        extensions=_C,
        severity="medium",
    ),
]

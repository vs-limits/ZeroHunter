"""C++ — XXE sinks (Xerces-C, Qt, Poco XML)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xxe"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-xxe-xerces-parser",
        function="XercesDOMParser::parse / SAXParser::parse",
        call_regex=r"\b(?:XercesDOMParser|SAXParser|SAX2XMLReader)\b[\s\S]{0,40}\.\s*parse\s*\(",
        description="Xerces-C parser without setDisableDefaultEntityResolution.",
        argument_roles=["source"],
        extensions=_CPP,
        severity="high",
    ),
    SinkRule(
        id="cpp-xxe-qxml-reader",
        function="QXmlStreamReader / QDomDocument::setContent",
        call_regex=r"\bQ(?:XmlStreamReader|DomDocument)\b[\s\S]{0,40}\.\s*(?:setContent|readNext)\s*\(",
        description="Qt XML parsing of untrusted XML.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-xxe-pugixml-load",
        function="pugi::xml_document::load_string / load_buffer",
        call_regex=r"\b(?:pugi\s*::\s*)?xml_document\b[\s\S]{0,40}\.\s*load(?:_string|_buffer|_file)?\s*\(",
        description="pugixml load of untrusted XML — verify load options.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-xxe-poco-xml",
        function="Poco::XML::DOMParser / SAXParser",
        call_regex=r"\bPoco\s*::\s*XML\s*::\s*(?:DOM|SAX)Parser\b",
        description="Poco XML parser default settings allow external entities.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
]

"""PHP — XML External Entity (XXE) sinks (CWE-611)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xxe"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-xxe-libxml-loadxml",
        function="DOMDocument::loadXML / SimpleXMLElement",
        call_regex=r"\b(?:DOMDocument|SimpleXMLElement)\s*\(?",
        description="XML parser objects. Without LIBXML_NOENT/LIBXML_DTDLOAD off they may resolve external entities.",
        argument_roles=["xml"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-xxe-simplexml-load-string",
        function="simplexml_load_string / simplexml_load_file",
        call_regex=r"\bsimplexml_load_(?:string|file)\s*\(",
        description="Procedural XML loaders; XXE risk when loading untrusted XML.",
        argument_roles=["xml"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-xxe-libxml-disable-entity-loader",
        function="libxml_disable_entity_loader(false)",
        call_regex=r"\blibxml_disable_entity_loader\s*\(\s*false\s*\)",
        description="Re-enables external entity loading globally.",
        argument_roles=["disable"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-xxe-xmlreader-open",
        function="XMLReader::open",
        call_regex=r"->\s*open\s*\(",
        description="XMLReader::open with default flags allows external entities.",
        argument_roles=["uri", "encoding", "options"],
        extensions=_PHP,
        severity="medium",
    ),
]

"""Python — XXE / XML External Entity sinks (CWE-611)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xxe"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-xxe-lxml-parse",
        function="lxml.etree.parse / fromstring",
        call_regex=r"\b(?:etree\.)?(?:parse|fromstring|XMLParser)\s*\(",
        description="lxml parser without resolve_entities=False or no_network=True allows XXE.",
        argument_roles=["source"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-xxe-xml-etree",
        function="xml.etree.ElementTree.parse",
        call_regex=r"\bElementTree\.\s*(?:parse|fromstring)\s*\(",
        description="Standard library ElementTree parser; vulnerable on older CPython.",
        argument_roles=["source"],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-xxe-minidom-parse",
        function="xml.dom.minidom.parse / parseString",
        call_regex=r"\bminidom\.\s*(?:parse|parseString)\s*\(",
        description="minidom parses external entities by default.",
        argument_roles=["source"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-xxe-sax-parse",
        function="xml.sax.parse / parseString",
        call_regex=r"\bxml\.sax\.\s*(?:parse|parseString)\s*\(",
        description="xml.sax expat parser allows XXE if external-general-entities feature stays on.",
        argument_roles=["source"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-xxe-pulldom",
        function="xml.dom.pulldom.parse",
        call_regex=r"\bpulldom\.\s*parse(?:String)?\s*\(",
        description="pulldom parser inherits expat XXE behavior.",
        argument_roles=["source"],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-xxe-xmlrpc-client",
        function="xmlrpc.client.loads / ServerProxy",
        call_regex=r"\bxmlrpc\.client\.\s*(?:loads|ServerProxy)\s*\(",
        description="xmlrpc client parses XML responses; entity expansion possible.",
        argument_roles=["data"],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-xxe-xmltodict",
        function="xmltodict.parse",
        call_regex=r"\bxmltodict\.\s*parse\s*\(",
        description="xmltodict uses expat under the hood.",
        argument_roles=["xml_input"],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-xxe-defusedxml-disabled",
        function="defusedxml.disable_defused_xml_libs",
        call_regex=r"\bdisable_defused_xml_libs\s*\(",
        description="Calling disable_defused_xml_libs re-enables unsafe parsers.",
        argument_roles=[],
        extensions=_PY,
        severity="critical",
    ),
]

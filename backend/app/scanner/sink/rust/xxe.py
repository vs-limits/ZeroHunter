"""Rust — XXE sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xxe"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-xxe-quickxml-from-str",
        function="quick-xml Reader::from_str",
        call_regex=r"\bReader\s*::\s*from_(?:str|reader)\s*\(",
        description="quick-xml reader — verify expansion limits.",
        argument_roles=["text"],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-xxe-roxmltree-parse",
        function="roxmltree::Document::parse",
        call_regex=r"\broxmltree\s*::\s*Document\s*::\s*parse\s*\(",
        description="roxmltree DOM parse of untrusted XML.",
        argument_roles=["text"],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-xxe-serde-xml-rs",
        function="serde-xml-rs from_str",
        call_regex=r"\bserde_xml_rs\s*::\s*from_(?:str|reader)\s*\(",
        description="serde-xml-rs (libxml-style) on untrusted input.",
        argument_roles=["s"],
        extensions=_RS,
        severity="medium",
    ),
]

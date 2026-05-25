"""Go — XXE sinks (CWE-611). encoding/xml only follows DTDs when Strict=false."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xxe"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-xxe-xml-decoder-strict-false",
        function="d.Strict = false",
        call_regex=r"\.\s*Strict\s*=\s*false",
        description="encoding/xml decoder with Strict disabled processes DTD / entities.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-xxe-xml-decoder-charsetreader-net",
        function="d.CharsetReader fetching external charset",
        call_regex=r"\.\s*CharsetReader\s*=",
        description="Custom CharsetReader may fetch external resources.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-xxe-libxml2-binding",
        function="xmlreader.Parse (libxml2 binding)",
        call_regex=r"libxml2|xmlreader\.\s*Parse\s*\(",
        description="Custom libxml2 binding likely vulnerable by default.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
]

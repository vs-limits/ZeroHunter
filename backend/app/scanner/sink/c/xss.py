"""C — XSS sinks in CGI/FastCGI output."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xss"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-xss-cgi-printf-html",
        function="printf(\"<...%s...>\", userInput)",
        call_regex=r"\b(?:printf|fprintf|puts|fputs)\s*\(",
        description="CGI program writing untrusted value into HTML response body.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
        extra_match_regex=[r"<[a-zA-Z]", r"</[a-zA-Z]", r"%s.*>"],
    ),
    SinkRule(
        id="c-xss-mongoose-write",
        function="mg_http_reply(... html ...)",
        call_regex=r"\bmg_(?:http_reply|printf|send)\s*\(",
        description="mongoose HTTP reply containing unescaped HTML.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
]

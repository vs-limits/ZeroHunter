"""C — CRLF / Header injection sinks (CGI/FastCGI)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "crlf_injection"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-crlf-fprintf-stdout-header",
        function="fprintf(stdout, \"Location: %s\\r\\n\", userInput)",
        call_regex=r"\bfprintf\s*\(\s*stdout\s*,\s*\"[A-Za-z\-]+\s*:\s*%s",
        description="CGI program writing HTTP header value from user input.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-crlf-printf-header",
        function="printf(\"Set-Cookie: %s\\r\\n\", userInput)",
        call_regex=r"\bprintf\s*\(\s*\"(?:Set-Cookie|Location|Content-Type)\s*:",
        description="CGI Set-Cookie / Location header built from user input.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-crlf-fcgi-puts",
        function="FCGI_printf / FCGI_puts",
        call_regex=r"\bFCGI_(?:printf|puts)\s*\(",
        description="FastCGI writing headers/body containing user input.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
]

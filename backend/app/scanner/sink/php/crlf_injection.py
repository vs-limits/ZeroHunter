"""PHP — CRLF / Header Injection sinks (CWE-93/113)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "crlf_injection"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-crlf-header-dynamic",
        function="header()",
        call_regex=r"\bheader\s*\(\s*['\"][^)]*\$",
        description="header() with a tainted value can let attacker inject CRLF / split response.",
        argument_roles=["header"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-crlf-setcookie-dynamic",
        function="setcookie / setrawcookie",
        call_regex=r"\b(?:setcookie|setrawcookie)\s*\(",
        description="setcookie() with tainted name/value/path can inject headers.",
        argument_roles=["name", "value", "path", "domain", "secure", "httponly"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-crlf-mail-headers",
        function="mail() additional_headers",
        call_regex=r"\bmail\s*\([^,]+,[^,]+,[^,]+,",
        description="mail() additional_headers parameter is a common CRLF target.",
        argument_roles=["to", "subject", "message", "headers", "params"],
        extensions=_PHP,
        severity="high",
    ),
]

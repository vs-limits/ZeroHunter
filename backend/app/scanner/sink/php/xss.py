"""PHP — XSS sinks (CWE-79). Reflected & DOM."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xss"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-xss-echo-superglobal",
        function="echo/print of superglobal",
        call_regex=r"\b(?:echo|print)\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b",
        description="Echoes a superglobal value directly to the response body.",
        argument_roles=["value"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-xss-printf-superglobal",
        function="printf with superglobal",
        call_regex=r"\b(?:printf|vprintf)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)",
        description="printf format string contains superglobal data.",
        argument_roles=["format", "value"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-xss-short-echo-tag",
        function="<?= $tainted ?>",
        call_regex=r"<\?=\s*\$",
        description="PHP short echo tag; flag for XSS review on tainted vars.",
        argument_roles=["value"],
        extensions=[".php", ".phtml"],
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-xss-html-output-htmlspecialchars-decode",
        function="htmlspecialchars_decode",
        call_regex=r"\bhtmlspecialchars_decode\s*\(",
        description="Decoding previously escaped HTML can re-introduce XSS.",
        argument_roles=["string"],
        extensions=_PHP,
        severity="medium",
    ),
    SinkRule(
        id="php-xss-twig-raw-filter",
        function="Twig |raw filter",
        # Twig-only — including .php matched every bitwise `$a | rawXxx()` and
        # produced large amounts of false positives in normal PHP code.
        call_regex=r"\|\s*raw\b",
        description="Twig |raw filter disables HTML escaping.",
        argument_roles=["expression"],
        extensions=[".twig"],
        severity="medium",
    ),
    SinkRule(
        id="php-xss-blade-unescaped",
        function="Blade {!! $... !!}",
        call_regex=r"\{!!\s*\$",
        description="Blade unescaped echo prints raw HTML.",
        argument_roles=["expression"],
        extensions=[".blade.php"],
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-xss-error-message",
        function="echo with error / message vars",
        call_regex=r"\b(?:echo|print)\s+[^;]*\$(?:error|message|msg|err)\b",
        description="Direct echo of error/message variables that often carry user input.",
        argument_roles=["value"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
]

"""PHP — Information Disclosure sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-info-phpinfo",
        function="phpinfo",
        call_regex=r"\bphpinfo\s*\(",
        description="phpinfo() leaks build/env info.",
        argument_roles=["what"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-info-error-reporting-display",
        function="display_errors enabled",
        call_regex=r"\bini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(?:1|on|true)",
        description="Re-enables display_errors at runtime.",
        argument_roles=["key", "value"],
        extensions=_PHP,
        severity="medium",
    ),
    SinkRule(
        id="php-info-print-r-debug",
        function="var_dump / print_r to output",
        call_regex=r"\b(?:var_dump|print_r|var_export)\s*\(",
        description="Debug dumpers leaking internal state when reachable from response.",
        argument_roles=["value"],
        extensions=_PHP,
        severity="low",
    ),
    SinkRule(
        id="php-info-debug-backtrace",
        function="debug_backtrace echo",
        call_regex=r"\b(?:echo|print|print_r|var_dump)\s*\(\s*debug_backtrace\s*\(",
        description="Echoing debug_backtrace leaks code paths.",
        argument_roles=["value"],
        extensions=_PHP,
        severity="medium",
    ),
]

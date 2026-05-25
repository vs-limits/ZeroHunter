"""PHP — CSRF heuristics (CWE-352).

Static detection for missing CSRF token verification is hard. We flag
state-changing handlers that read $_POST / $_GET inputs as candidates
for Auditor to manually verify token usage.
"""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "csrf"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-csrf-state-change-post",
        function="state-change handler reading $_POST",
        # Only fire when a state-mutating verb is on the same line as $_POST
        # — every PHP form reads $_POST 5-50 times, so the legacy unrestricted
        # pattern dominated reports.
        call_regex=r"\$_POST\s*\[\s*['\"][^'\"]+['\"]\s*\]",
        description="$_POST read inside a state-changing operation; flag for CSRF token verification audit.",
        argument_roles=["field"],
        extensions=_PHP,
        severity="low",
        extra_match_regex=[
            r"\b(?:INSERT|UPDATE|DELETE|REPLACE|DROP|TRUNCATE)\b",
            r"->\s*(?:save|update|insert|delete|create|store|destroy|remove)\s*\(",
            r"\bunlink\s*\(|\brename\s*\(|\bmove_uploaded_file\s*\(",
        ],
    ),
    SinkRule(
        id="php-csrf-laravel-skip-token",
        function="VerifyCsrfToken middleware skip",
        call_regex=r"protected\s+\$except\s*=\s*\[",
        description="Laravel CSRF except[] skips token verification on listed routes.",
        argument_roles=["routes"],
        extensions=_PHP,
        severity="medium",
    ),
]

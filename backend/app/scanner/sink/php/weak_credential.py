"""PHP — Weak Credential / hardcoded secret sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-weak-md5-password",
        function="md5 / sha1 for passwords",
        call_regex=r"\b(?:md5|sha1)\s*\([^)]*(?:pass|password|pwd)\b",
        description="md5/sha1 used for password storage. Use password_hash + bcrypt/argon2.",
        argument_roles=["value"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-weak-rand-token",
        function="rand / mt_rand for tokens",
        call_regex=r"\b(?:rand|mt_rand|uniqid|microtime)\s*\(",
        description="Non-cryptographic randomness used for tokens/secrets.",
        argument_roles=["min", "max"],
        extensions=_PHP,
        severity="medium",
    ),
    SinkRule(
        id="php-weak-hardcoded-credentials",
        function="hardcoded credential",
        call_regex=r"(?:password|secret|api_?key|access_?key|token)\s*=\s*['\"][^'\"\s]{6,}['\"]",
        description="Likely hardcoded credential / API key in source.",
        argument_roles=["value"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-weak-password-default",
        function="default 'password'/'admin' constants",
        call_regex=r"['\"](?:admin|root|password|123456|qwerty)['\"]",
        description="Default-looking string credential in source.",
        argument_roles=["value"],
        extensions=_PHP,
        severity="low",
    ),
]

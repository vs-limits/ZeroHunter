"""Rust — Weak / Hardcoded Credential sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-cred-let-password",
        function="let password = \"...\"",
        call_regex=r"\blet\s+(?:password|passwd|pwd)\s*=\s*\"[^\"]+\"",
        description="Hardcoded password binding.",
        argument_roles=[],
        extensions=_RS,
        severity="high",
    ),
    SinkRule(
        id="rs-cred-const-apikey",
        function="const API_KEY: &str = \"...\"",
        call_regex=r"\bconst\s+(?:API_KEY|APIKEY|SECRET_KEY|ACCESS_TOKEN|CLIENT_SECRET)\s*:\s*&str\s*=\s*\"",
        description="Hardcoded API key constant.",
        argument_roles=[],
        extensions=_RS,
        severity="critical",
    ),
    SinkRule(
        id="rs-cred-aws-akid",
        function="AKIA... access key",
        call_regex=r"AKIA[0-9A-Z]{16}",
        description="AWS access key id pattern.",
        argument_roles=[],
        extensions=_RS,
        severity="critical",
    ),
    SinkRule(
        id="rs-cred-pem-block",
        function="PEM private key in source",
        call_regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="Embedded private key material.",
        argument_roles=[],
        extensions=_RS,
        severity="critical",
    ),
    SinkRule(
        id="rs-cred-rand-thread-rng-token",
        function="rand::thread_rng for security",
        call_regex=r"\bthread_rng\s*\(\s*\)",
        description="thread_rng is not constant-time and seedable; for secrets use rand::rngs::OsRng.",
        argument_roles=[],
        extensions=_RS,
        severity="low",
    ),
]

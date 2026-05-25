"""Go — Weak / Hardcoded Credential sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-cred-hardcoded-password",
        function="password literal",
        call_regex=r"\b(?:password|passwd|pwd)\s*:?=\s*\"[^\"]+\"",
        description="Hardcoded password literal.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-cred-apikey-literal",
        function="apiKey / secretKey literal",
        call_regex=r"\b(?:apiKey|apikey|secretKey|accessToken|clientSecret)\s*:?=\s*\"[A-Za-z0-9_\-/+=]{8,}\"",
        description="Hardcoded API key.",
        argument_roles=[],
        extensions=_GO,
        severity="critical",
    ),
    SinkRule(
        id="go-cred-aws-akid",
        function="AKIA... pattern",
        call_regex=r"AKIA[0-9A-Z]{16}",
        description="AWS access key id pattern.",
        argument_roles=[],
        extensions=_GO,
        severity="critical",
    ),
    SinkRule(
        id="go-cred-rand-math",
        function="math/rand for token",
        call_regex=r"\"math/rand\"",
        description="math/rand is not cryptographically secure; use crypto/rand.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-cred-pem-block",
        function="PEM private key embedded",
        call_regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="Embedded private key material.",
        argument_roles=[],
        extensions=_GO,
        severity="critical",
    ),
]

"""C — Weak Credential / Hardcoded Secret sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-cred-hardcoded-password",
        function="char password[] = \"...\"",
        call_regex=r"\b(?:char|const\s+char)\s*\*?\s*(?:password|passwd|pwd)\s*\[?\s*\]?\s*=\s*\"[^\"]+\"",
        description="Hardcoded password literal.",
        argument_roles=[],
        extensions=_C,
        severity="high",
    ),
    SinkRule(
        id="c-cred-apikey-literal",
        function="char API_KEY[] = \"...\"",
        call_regex=r"\b(?:API_KEY|APIKEY|SECRET_KEY|ACCESS_TOKEN|CLIENT_SECRET)\s*\[?\s*\]?\s*=\s*\"[A-Za-z0-9_\-/+=]{8,}\"",
        description="Hardcoded API key.",
        argument_roles=[],
        extensions=_C,
        severity="critical",
    ),
    SinkRule(
        id="c-cred-pem-block",
        function="PEM private key embedded",
        call_regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="Embedded private key material.",
        argument_roles=[],
        extensions=_C,
        severity="critical",
    ),
    SinkRule(
        id="c-cred-rand-not-secure",
        function="rand() / srand(time(NULL))",
        call_regex=r"\b(?:rand|random|srand)\s*\(",
        description="rand()/random() are not cryptographically secure.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-cred-md5-init",
        function="MD5_Init / SHA1_Init for password",
        call_regex=r"\b(?:MD5_Init|SHA1_Init|MD5|SHA1)\s*\(",
        description="MD5/SHA1 hashing of password (legacy OpenSSL).",
        argument_roles=[],
        extensions=_C,
        severity="high",
    ),
    SinkRule(
        id="c-cred-memcmp-password",
        function="memcmp on credential (not constant time)",
        call_regex=r"\b(?:memcmp|strcmp|strncmp|bcmp)\s*\(",
        description="memcmp/strcmp on credentials leaks timing — use CRYPTO_memcmp.",
        argument_roles=["s1", "s2", "n"],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
]

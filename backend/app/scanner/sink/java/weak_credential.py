"""Java — Weak Credential / Hardcoded Secret sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_JAVA = [".java", ".kt", ".scala"]
_CFG = [".properties", ".yml", ".yaml", ".xml"]

RULES = [
    SinkRule(
        id="java-cred-hardcoded-password",
        function="String password = \"...\"",
        call_regex=r"\bString\s+(?:password|passwd|pwd)\s*=\s*\"[^\"]+\"",
        description="Hardcoded password literal.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-cred-apikey-literal",
        function="apiKey/clientSecret literal",
        call_regex=r"\b(?:apiKey|apikey|secretKey|accessToken|clientSecret)\s*=\s*\"[A-Za-z0-9_\-/+=]{8,}\"",
        description="Hardcoded API key / secret.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-cred-aws-akid",
        function="AKIA... access key",
        call_regex=r"AKIA[0-9A-Z]{16}",
        description="AWS access key id literal.",
        argument_roles=[],
        extensions=_JAVA + _CFG,
        severity="critical",
    ),
    SinkRule(
        id="java-cred-pem-block",
        function="PEM private key embedded",
        call_regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="Embedded private key.",
        argument_roles=[],
        extensions=_JAVA + _CFG,
        severity="critical",
    ),
    SinkRule(
        id="java-cred-random-not-secure",
        function="new Random() for token generation",
        call_regex=r"\bnew\s+Random\s*\(",
        description="java.util.Random is not cryptographically secure.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-cred-properties-password",
        function="*.password = literal in config",
        call_regex=r"^\s*[\w.-]*(?:password|passwd|secret)\s*=\s*[^\s$\n]+",
        description="Properties file with hard-coded password.",
        argument_roles=[],
        extensions=_CFG,
        severity="high",
    ),
    SinkRule(
        id="java-cred-md5-for-pw",
        function="MessageDigest MD5 of password",
        call_regex=r"MessageDigest\s*\.\s*getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"",
        description="MD5/SHA1 hashing of password.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
]

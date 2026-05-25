"""Python — Weak Credential / Hardcoded Secret sinks (CWE-259, CWE-798, CWE-521)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-cred-hardcoded-password",
        function="password = '...'",
        call_regex=r"\b(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{1,}['\"]",
        description="Hardcoded password literal.",
        argument_roles=[],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-cred-hardcoded-apikey",
        function="api_key = '...'",
        call_regex=r"\b(?:api[_-]?key|apikey|secret_key|access[_-]?token|client[_-]?secret)\s*=\s*['\"][A-Za-z0-9_\-/+=]{8,}['\"]",
        description="Hardcoded API key / token literal.",
        argument_roles=[],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-cred-aws-access-key",
        function="AWS access key literal",
        call_regex=r"\bAKIA[0-9A-Z]{16}\b",
        description="AWS access key id pattern.",
        argument_roles=[],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-cred-private-key-block",
        function="PEM private key embedded",
        call_regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="Private key material embedded in source.",
        argument_roles=[],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-cred-weak-random",
        function="random.* used for token",
        call_regex=r"\brandom\.\s*(?:randint|random|choice|choices|sample|uniform)\s*\(",
        description="random module is not cryptographically strong; use secrets.token_*.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-cred-default-admin-password",
        function="default admin credentials",
        call_regex=r"\b(?:admin|root)\s*[:=]\s*['\"](?:admin|password|123456|root)['\"]",
        description="Default-looking credentials.",
        argument_roles=[],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-cred-md5-password",
        function="md5/sha1 used as password hash",
        call_regex=r"\bhashlib\.\s*(?:md5|sha1)\s*\(\s*[^)]*(?:password|passwd|pwd)",
        description="Hashing password with MD5/SHA1 is unsafe.",
        argument_roles=["data"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-cred-base64-secret",
        function="base64.b64decode of secret literal",
        call_regex=r"\bb64decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
        description="Base64-encoded secret embedded (mild obfuscation only).",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
]

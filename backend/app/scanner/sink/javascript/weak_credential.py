"""JavaScript / Node.js — Weak Credential / Hardcoded Secret sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-cred-hardcoded-password",
        function="password = '...'",
        call_regex=r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{1,}['\"]",
        description="Hardcoded password literal.",
        argument_roles=[],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-cred-hardcoded-apikey",
        function="apiKey = '...'",
        call_regex=r"\b(?:api[_-]?key|apikey|secret_key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{8,}['\"]",
        description="Hardcoded API key / token literal.",
        argument_roles=[],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-cred-aws-access-key",
        function="AWS access key id literal",
        call_regex=r"\bAKIA[0-9A-Z]{16}\b",
        description="AWS access key id pattern.",
        argument_roles=[],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-cred-pem-private-key",
        function="PEM private key embedded",
        call_regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="Private key material embedded in source.",
        argument_roles=[],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-cred-math-random-secret",
        function="Math.random() for token",
        call_regex=r"\bMath\s*\.\s*random\s*\(",
        description="Math.random is not cryptographically secure; use crypto.randomBytes.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-cred-md5-sha1-password",
        function="crypto.createHash('md5'|'sha1') of password",
        call_regex=r"\bcreateHash\s*\(\s*['\"](?:md5|sha1)['\"]",
        description="MD5/SHA1 used for password hashing.",
        argument_roles=["algorithm"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-cred-default-creds",
        function="default admin/admin credentials",
        call_regex=r"\b(?:admin|root)\s*[:=]\s*['\"](?:admin|password|123456|root)['\"]",
        description="Default-looking credential pair.",
        argument_roles=[],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-cred-jwt-shared-secret-weak",
        function="jwt secret length < 32",
        call_regex=r"\bjwt\s*\.\s*sign\s*\([^,)]+,\s*['\"][^'\"]{1,16}['\"]",
        description="HMAC secret too short for HS256.",
        argument_roles=["payload", "secret"],
        extensions=_JS,
        severity="medium",
    ),
]

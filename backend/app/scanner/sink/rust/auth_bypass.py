"""Rust — Authentication Bypass sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-auth-jwt-no-verify",
        function="jsonwebtoken::dangerous_insecure_decode",
        call_regex=r"\bdangerous_insecure_decode(?:_with_validation)?\s*\(",
        description="jsonwebtoken's *_insecure_decode skips signature verification.",
        argument_roles=["token"],
        extensions=_RS,
        severity="critical",
    ),
    SinkRule(
        id="rs-auth-jwt-validation-disabled",
        function="Validation { insecure_disable_signature_validation: true }",
        call_regex=r"insecure_disable_signature_validation\s*:\s*true",
        description="Validation explicitly disables signature check.",
        argument_roles=[],
        extensions=_RS,
        severity="critical",
    ),
    SinkRule(
        id="rs-auth-tls-acceptdanger",
        function="danger_accept_invalid_certs(true)",
        call_regex=r"\.\s*danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)",
        description="reqwest/rustls accepting invalid certs/hostnames.",
        argument_roles=[],
        extensions=_RS,
        severity="high",
    ),
    SinkRule(
        id="rs-auth-password-eq",
        function="password == comparison",
        call_regex=r"\b(?:password|passwd|pwd|secret|token)\s*==",
        description="Comparing credentials with == is not constant-time.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-auth-md5-password",
        function="md5/sha1 used for password",
        call_regex=r"\b(?:md5|sha1)\s*::\s*compute\s*\(|\bMd5\s*::\s*new\s*\(",
        description="MD5/SHA1 hashing of password.",
        argument_roles=[],
        extensions=_RS,
        severity="high",
    ),
]

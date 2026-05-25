"""Go — Authentication Bypass sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-auth-jwt-parse-noverify",
        function="jwt.Parse with empty key func / alg none",
        call_regex=r"\bjwt\s*\.\s*(?:Parse|ParseWithClaims)\s*\(",
        description="jwt-go Parse — verify key func rejects 'none' and validates alg.",
        argument_roles=["tokenString", "keyFunc"],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-auth-bytes-equal-pw",
        function="bytes.Equal on password (use ConstantTimeCompare)",
        call_regex=r"\bbytes\s*\.\s*Equal\s*\(",
        description="bytes.Equal on credentials is not constant time.",
        argument_roles=["a", "b"],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-auth-string-equal-pw",
        function="password == comparison",
        call_regex=r"\b(?:password|passwd|pwd|secret|token)\s*==",
        description="Direct comparison of credentials.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-auth-md5-sha1-password",
        function="md5.Sum / sha1.Sum on password",
        call_regex=r"\b(?:md5|sha1)\s*\.\s*(?:Sum|New)\s*\(",
        description="MD5/SHA1 used for password hashing.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-auth-no-tls-verify",
        function="InsecureSkipVerify: true",
        call_regex=r"InsecureSkipVerify\s*:\s*true",
        description="TLS verification disabled.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
]

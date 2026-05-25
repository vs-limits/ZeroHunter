"""Java — Authentication Bypass sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-auth-jwt-parse-noverify",
        function="Jwts.parser().parseClaimsJwt (unsigned)",
        call_regex=r"\bparseClaimsJwt\s*\(|\bparsePlaintextJwt\s*\(",
        description="jjwt parses without verifying signature.",
        argument_roles=["jwt"],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-auth-jwt-alg-none",
        function="JWT alg=none",
        call_regex=r"SignatureAlgorithm\s*\.\s*NONE",
        description="Explicit `none` JWT algorithm.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-auth-string-equals-pw",
        function="String#equals on password without timing-safe compare",
        call_regex=r"\b(?:password|pwd|passwd|secret|token)[A-Za-z]*\s*\.\s*equals\s*\(",
        description="String.equals on credential — timing side-channel.",
        argument_roles=["other"],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-auth-md5-password",
        function="MessageDigest.getInstance(\"MD5\"/\"SHA1\") on password",
        call_regex=r"MessageDigest\s*\.\s*getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"",
        description="MD5/SHA1 used to hash credentials.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-auth-permitall",
        function="permitAll() on protected route",
        call_regex=r"\.\s*permitAll\s*\(\s*\)",
        description="Spring Security permitAll() — verify which routes it covers.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-auth-disable-https",
        function="requiresChannel().anyRequest().requiresInsecure",
        call_regex=r"\.\s*requiresInsecure\s*\(",
        description="Channel security downgraded to plain HTTP.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-auth-h2-console",
        function="H2 console enabled",
        call_regex=r"spring\.h2\.console\.enabled\s*=\s*true",
        description="H2 console exposed — historic RCE.",
        argument_roles=[],
        extensions=_JAVA + [".properties", ".yml", ".yaml"],
        severity="critical",
    ),
]

"""C++ — Weak / Hardcoded Credential sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-cred-string-password",
        function="std::string password = \"...\"",
        call_regex=r"\b(?:std\s*::\s*)?string\s+(?:password|passwd|pwd)\s*=\s*\"[^\"]+\"",
        description="Hardcoded password literal.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
    ),
    SinkRule(
        id="cpp-cred-const-apikey",
        function="constexpr API_KEY",
        call_regex=r"\b(?:constexpr|const)\s+(?:auto|char\s*\*?\s*const|std\s*::\s*string(?:_view)?)\s+(?:API_KEY|APIKEY|SECRET_KEY|ACCESS_TOKEN|CLIENT_SECRET)\s*=\s*\"",
        description="Hardcoded API key constant.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
    ),
    SinkRule(
        id="cpp-cred-pem-block",
        function="PEM private key embedded",
        call_regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="Embedded private key material.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
    ),
    SinkRule(
        id="cpp-cred-mt19937-token",
        function="std::mt19937 for token",
        call_regex=r"\bstd\s*::\s*mt19937(?:_64)?\b",
        description="Mersenne Twister isn't cryptographically secure.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-cred-md5-evp",
        function="EVP_md5() / EVP_sha1() for password",
        call_regex=r"\bEVP_(?:md5|sha1)\s*\(",
        description="MD5/SHA1 used for password hashing.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
    ),
]

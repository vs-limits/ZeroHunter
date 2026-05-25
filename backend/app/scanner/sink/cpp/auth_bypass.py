"""C++ — Authentication Bypass sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-auth-strcmp-pw",
        function="strcmp on password not constant time",
        call_regex=r"\b(?:std\s*::\s*)?str(?:n?cmp|case(?:n)?cmp)\s*\([^,)]+(?:password|passwd|pwd|secret|token)",
        description="String compare of credentials.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-auth-string-eq-pw",
        function="std::string == password",
        call_regex=r"\b(?:password|passwd|pwd|secret|token)\s*==",
        description="Password compared via operator== — timing side-channel.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-auth-ssl-verify-none",
        function="SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ...)",
        call_regex=r"\bSSL_(?:CTX_)?set_verify\s*\([^,]+,\s*SSL_VERIFY_NONE",
        description="OpenSSL TLS verification disabled.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
    ),
    SinkRule(
        id="cpp-auth-curl-disable-verify",
        function="CURLOPT_SSL_VERIFYPEER set to 0",
        call_regex=r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*0",
        description="libcurl peer/host verification disabled.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
    ),
    SinkRule(
        id="cpp-auth-qsslconfig-noverify",
        function="QSslConfiguration setPeerVerifyMode(QSslSocket::VerifyNone)",
        call_regex=r"VerifyNone",
        description="Qt SSL peer verification disabled.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
    ),
]

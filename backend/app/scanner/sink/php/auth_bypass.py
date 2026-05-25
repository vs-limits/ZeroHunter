"""PHP — Authentication Bypass / loose-comparison patterns (CWE-287)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-auth-loose-equals-password",
        function="$_POST password loose ==",
        call_regex=r"\$_(?:POST|GET|REQUEST)\s*\[\s*['\"](?:pass|password|pwd|token|hash)['\"]\s*\]\s*==[^=]",
        description="Loose-comparison (==) on a credential field is a classic PHP type juggling bypass.",
        argument_roles=["lhs"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-auth-strcmp-loose",
        function="strcmp loose check",
        call_regex=r"\bstrcmp\s*\([^)]*\$_(?:POST|GET|REQUEST)",
        description="strcmp() returns NULL when given an array, leading to == 0 bypass.",
        argument_roles=["a", "b"],
        extensions=_PHP,
        severity="medium",
    ),
    SinkRule(
        id="php-auth-md5-equals",
        function="md5 == constant",
        call_regex=r"\bmd5\s*\([^)]*\)\s*==\s*['\"]0e",
        description="md5(...) == '0e...' magic-hash bypass via type juggling.",
        argument_roles=["lhs", "rhs"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-auth-jwt-decode-no-verify",
        function="firebase/JWT::decode without secret",
        call_regex=r"JWT\s*::\s*decode\s*\(",
        description="JWT::decode without a strong key/algorithm config is unsafe.",
        argument_roles=["token", "key", "algs"],
        extensions=_PHP,
        severity="medium",
    ),
]

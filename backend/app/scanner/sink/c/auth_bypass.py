"""C — Auth bypass sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = 'auth_bypass'

RULES = [
    SinkRule(
        id='c-auth-strcmp-password',
        function='strcmp(password, expected) == 0',
        call_regex=r"\bstr(?:n?cmp|case(?:n)?cmp)\s*\([^,)]+(?:password|passwd|pwd|secret|token)",
        description='Comparing credential with strcmp leaks timing.',
        argument_roles=['a', 'b', 'n'],
        extensions=['.c', '.h'],
        severity='medium',
    ),
    SinkRule(
        id='c-auth-memcmp-tag',
        function='memcmp on MAC / token (use CRYPTO_memcmp)',
        call_regex=r"\bmemcmp\s*\(",
        description='memcmp on MAC/HMAC/token output is not constant time.',
        argument_roles=['s1', 's2', 'n'],
        extensions=['.c', '.h'],
        severity='medium',
    ),
    SinkRule(
        id='c-auth-setuid-zero',
        function='setuid(0) / seteuid(0)',
        call_regex=r"\b(?:setuid|seteuid|setresuid)\s*\(\s*0",
        description="Escalating to root — verify caller-controlled paths can't reach here.",
        argument_roles=[],
        extensions=['.c', '.h'],
        severity='high',
    ),
    SinkRule(
        id='c-auth-pam-conv-allow',
        function='pam conv always-yes',
        call_regex='PAM_SUCCESS',
        description='pam custom conv returning PAM_SUCCESS unconditionally — bypass.',
        argument_roles=[],
        extensions=['.c', '.h'],
        severity='medium',
    ),
]

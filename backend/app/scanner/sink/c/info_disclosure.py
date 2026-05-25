"""C — Information Disclosure sinks (CWE-200, CWE-457)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-info-uninitialized-malloc",
        function="malloc without subsequent memset",
        call_regex=r"\bmalloc\s*\(",
        description="malloc returns uninitialised memory — followed-by sends may leak heap.",
        argument_roles=["size"],
        extensions=_C,
        severity="low",
    ),
    SinkRule(
        id="c-info-perror-tainted",
        function="perror with sensitive context",
        call_regex=r"\bperror\s*\(",
        description="perror prints errno text — confirm caller doesn't include secret.",
        argument_roles=["s"],
        extensions=_C,
        severity="low",
    ),
    SinkRule(
        id="c-info-stack-printf",
        function="printf(\"%p\", localvar) addr leak",
        call_regex=r"%p",
        description="Leaking pointer/format addresses defeats ASLR.",
        argument_roles=[],
        extensions=_C,
        severity="low",
    ),
    SinkRule(
        id="c-info-getenv-print",
        function="getenv(\"AWS_*\") / printf",
        call_regex=r"\bgetenv\s*\(\s*\"(?:AWS_|GCP_|AZURE_|SECRET|TOKEN|KEY)",
        description="Reading credential-shaped env into output.",
        argument_roles=["name"],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-info-syslog-cred",
        function="syslog logging credential",
        call_regex=r"\bsyslog\s*\([^)]*(?:password|secret|token|api[_-]?key)",
        description="syslog of credential-named variable.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
    ),
]

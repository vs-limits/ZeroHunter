"""C++ — Information Disclosure sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-info-cerr-stack",
        function="std::cerr << std::current_exception() / backtrace",
        call_regex=r"\bstd\s*::\s*cerr\s*<<",
        description="Dumping exception/backtrace via cerr can leak path information.",
        argument_roles=[],
        extensions=_CPP,
        severity="low",
    ),
    SinkRule(
        id="cpp-info-qdebug-secret",
        function="qDebug() << password/token",
        call_regex=r"\bqDebug\s*\(\s*\)\s*<<[^;]*(?:password|secret|token|api[_-]?key)",
        description="qDebug stream containing credential variable.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-info-spdlog-secret",
        function="spdlog::*(secret)",
        call_regex=r"\bspdlog\s*::\s*(?:trace|debug|info|warn|error|critical)\s*\([^)]*(?:password|secret|token|api[_-]?key)",
        description="spdlog logging credential-named binding.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-info-getenv-print",
        function="getenv(\"AWS_*\") leaked",
        call_regex=r"\bgetenv\s*\(\s*\"(?:AWS_|GCP_|AZURE_|SECRET|TOKEN|KEY|PASSWORD)",
        description="Reading credential env then output.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
]

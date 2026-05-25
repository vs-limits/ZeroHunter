"""Go — Information Disclosure sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-info-pprof-handler",
        function="net/http/pprof imported",
        call_regex=r"\"net/http/pprof\"",
        description="pprof import side-effect mounts debug handlers on default mux.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-info-expvar-handler",
        function="expvar imported",
        call_regex=r"\"expvar\"",
        description="expvar publishes /debug/vars on default mux.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-info-panic-response",
        function="panic message written to response",
        call_regex=r"\.\s*Write\s*\(\s*\[\]byte\s*\(\s*err\s*\.\s*Error\s*\(\s*\)",
        description="Writing err.Error() to client leaks internals.",
        argument_roles=[],
        extensions=_GO,
        severity="low",
    ),
    SinkRule(
        id="go-info-env-print",
        function="os.Environ() in response",
        call_regex=r"\bos\s*\.\s*Environ\s*\(\s*\)",
        description="Dumping environment can expose secrets.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-info-log-with-secret",
        function="log.Printf with password/token",
        call_regex=r"\blog\s*\.\s*(?:Printf|Println|Print|Errorf|Fatalf|Panicf)\s*\([^)]*(?:password|secret|token|api[_-]?key)",
        description="Logging variable named like credential.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
]

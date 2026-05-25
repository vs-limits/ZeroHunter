"""C — File / Module Inclusion sinks (dlopen-style)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_inclusion"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-incl-dlopen-path",
        function="dlopen(userPath, ...)",
        call_regex=r"\bdlopen\s*\(",
        description="Loading shared library by caller-supplied path.",
        argument_roles=["filename", "flags"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-incl-loadlibrary",
        function="LoadLibrary / LoadLibraryEx",
        call_regex=r"\bLoadLibrary(?:Ex)?(?:A|W)?\s*\(",
        description="Windows LoadLibrary with caller-controlled path.",
        argument_roles=["lpLibFileName"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-incl-include-from-getenv",
        function="loading from $PWD / $HOME without sanitisation",
        call_regex=r"\bgetenv\s*\(\s*\"(?:PWD|HOME|TMPDIR|USER)\"",
        description="Resolving include path from user-controlled env can be hijacked.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
    ),
]

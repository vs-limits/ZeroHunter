"""C++ — File / Plugin Inclusion sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_inclusion"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-incl-qpluginloader",
        function="QPluginLoader::setFileName(userPath)",
        call_regex=r"\bQPluginLoader\b[\s\S]{0,40}\.\s*setFileName\s*\(",
        description="Qt plugin path from caller — arbitrary plugin load.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-incl-dlopen",
        function="dlopen(userPath, RTLD_NOW)",
        call_regex=r"\bdlopen\s*\(",
        description="Loading shared object from caller path.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-incl-loadlibrary",
        function="LoadLibrary(userPath) — Windows",
        call_regex=r"\bLoadLibrary(?:Ex)?(?:A|W)?\s*\(",
        description="Win32 LoadLibrary with caller-controlled path.",
        argument_roles=[],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
]

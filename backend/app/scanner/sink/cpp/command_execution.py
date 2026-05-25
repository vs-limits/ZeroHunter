"""C++ — Command Execution sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-cmd-system",
        function="std::system(cmd)",
        call_regex=r"\b(?:std\s*::\s*)?system\s*\(",
        description="std::system runs a shell command.",
        argument_roles=["command"],
        extensions=_CPP,
        severity="critical",
    ),
    SinkRule(
        id="cpp-cmd-popen",
        function="popen(cmd, mode)",
        call_regex=r"\bpopen\s*\(",
        description="popen via shell with user-controlled cmd.",
        argument_roles=["command", "type"],
        extensions=_CPP,
        severity="critical",
    ),
    SinkRule(
        id="cpp-cmd-boost-process",
        function="boost::process::system / spawn",
        call_regex=r"\bboost\s*::\s*process\s*::\s*(?:system|spawn|child)\s*\(",
        description="Boost.Process spawns child — argv injection if components are user-controlled.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-cmd-qprocess-start",
        function="QProcess::start / startCommand / startDetached",
        call_regex=r"\bQProcess\s*::\s*start(?:Detached|Command)?\s*\(|\.\s*start(?:Detached|Command)?\s*\(",
        description="Qt QProcess start with caller-supplied program string.",
        argument_roles=["program", "arguments"],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-cmd-createprocess",
        function="CreateProcess / CreateProcessW",
        call_regex=r"\bCreateProcess(?:A|W)?\s*\(",
        description="Win32 CreateProcess with caller-controlled command-line.",
        argument_roles=["lpApplicationName", "lpCommandLine"],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-cmd-shellexecute",
        function="ShellExecute / ShellExecuteEx",
        call_regex=r"\bShellExecute(?:Ex)?(?:A|W)?\s*\(",
        description="ShellExecute with caller-controlled lpFile/lpParameters.",
        argument_roles=["hwnd", "lpOperation", "lpFile", "lpParameters", "lpDirectory", "nShowCmd"],
        extensions=_CPP,
        severity="critical",
        require_dynamic=True,
    ),
]

"""Python — Command Execution sinks (CWE-78)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-cmd-os-system",
        function="os.system",
        call_regex=r"\bos\.system\s*\(",
        description="Executes a command through the shell.",
        argument_roles=["command"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-cmd-os-popen",
        function="os.popen",
        call_regex=r"\bos\.popen\s*\(",
        description="Opens a process pipe via the shell.",
        argument_roles=["command"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-cmd-subprocess",
        function="subprocess.run / Popen / call / check_output",
        call_regex=r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(",
        description="Subprocess primitives; shell=True with string command is high-risk.",
        argument_roles=["args", "shell"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-cmd-os-exec",
        function="os.execv* / os.spawn*",
        call_regex=r"\bos\.(?:exec(?:v|vp|ve|vpe|l|lp|le|lpe)|spawn(?:v|vp|ve|l|lp|le|lpe))\s*\(",
        description="Direct exec/spawn family; user-controlled program path is RCE.",
        argument_roles=["path", "args"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-cmd-shutil-which-then-call",
        function="commands.getoutput (Py2 legacy)",
        call_regex=r"\bcommands\.(?:getoutput|getstatusoutput|getstatus)\s*\(",
        description="Legacy commands module using sh -c; treated as shell exec.",
        argument_roles=["cmd"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-cmd-pty-spawn",
        function="pty.spawn",
        call_regex=r"\bpty\.spawn\s*\(",
        description="pty.spawn launches a child process under a pty.",
        argument_roles=["argv"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-cmd-asyncio-create-subprocess-shell",
        function="asyncio.create_subprocess_shell",
        call_regex=r"asyncio\.create_subprocess_shell\s*\(",
        description="Async shell subprocess.",
        argument_roles=["cmd"],
        extensions=_PY,
        severity="high",
    ),
]

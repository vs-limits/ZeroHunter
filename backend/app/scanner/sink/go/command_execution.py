"""Go — Command Execution sinks (CWE-78)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-cmd-exec-command",
        function="exec.Command(name, args...)",
        call_regex=r"\bexec\s*\.\s*Command(?:Context)?\s*\(",
        description="os/exec Command with dynamic name/args.",
        argument_roles=["name", "args"],
        extensions=_GO,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-cmd-exec-cmd-run",
        function="cmd.Run / Output / CombinedOutput / Start",
        call_regex=r"\.\s*(?:Run|Output|CombinedOutput|Start)\s*\(\s*\)",
        description="exec.Cmd execution methods — flag for argv injection.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-cmd-syscall-exec",
        function="syscall.Exec / ForkExec",
        call_regex=r"\bsyscall\s*\.\s*(?:Exec|ForkExec|Execve|StartProcess)\s*\(",
        description="syscall-level exec replaces or spawns process.",
        argument_roles=["argv0", "argv", "envv"],
        extensions=_GO,
        severity="critical",
    ),
    SinkRule(
        id="go-cmd-os-startprocess",
        function="os.StartProcess",
        call_regex=r"\bos\s*\.\s*StartProcess\s*\(",
        description="os.StartProcess with caller-supplied path/argv.",
        argument_roles=["name", "argv", "attr"],
        extensions=_GO,
        severity="critical",
    ),
    SinkRule(
        id="go-cmd-shell-via-sh-c",
        function="exec.Command('sh', '-c', userInput)",
        call_regex=r"exec\.Command\s*\(\s*\"(?:sh|bash|cmd\.exe|powershell)\"\s*,",
        description="Explicit shell command — args become a shell string.",
        argument_roles=[],
        extensions=_GO,
        severity="critical",
        require_dynamic=True,
    ),
]

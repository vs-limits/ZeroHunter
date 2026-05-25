"""C — Command Execution sinks (CWE-78)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-cmd-system",
        function="system(cmd)",
        call_regex=r"\bsystem\s*\(",
        description="system() spawns a shell with cmd — full command injection.",
        argument_roles=["command"],
        extensions=_C,
        severity="critical",
    ),
    SinkRule(
        id="c-cmd-popen",
        function="popen(cmd, mode)",
        call_regex=r"\bpopen\s*\(",
        description="popen() runs cmd via /bin/sh -c.",
        argument_roles=["command", "type"],
        extensions=_C,
        severity="critical",
    ),
    SinkRule(
        id="c-cmd-execl-family",
        function="execl / execlp / execle",
        call_regex=r"\bexec(?:l|lp|le)\s*\(",
        description="exec*l family with caller-supplied program path.",
        argument_roles=["path", "args"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-cmd-execv-family",
        function="execv / execvp / execve",
        call_regex=r"\bexec(?:v|vp|ve|vpe)\s*\(",
        description="exec*v family — argv injection if components are user-controlled.",
        argument_roles=["path", "argv"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-cmd-posix-spawn",
        function="posix_spawn / posix_spawnp",
        call_regex=r"\bposix_spawn(?:p)?\s*\(",
        description="posix_spawn family — RCE on attacker-controlled program/argv.",
        argument_roles=["pid", "path", "file_actions", "attrp", "argv", "envp"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-cmd-fork-exec",
        function="fork() then exec*",
        call_regex=r"\bfork\s*\(\s*\)",
        description="fork() — pair with subsequent exec* call review.",
        argument_roles=[],
        extensions=_C,
        severity="low",
    ),
    SinkRule(
        id="c-cmd-wordexp",
        function="wordexp(s, p, flags)",
        call_regex=r"\bwordexp\s*\(",
        description="wordexp() does shell-style expansion — command injection class.",
        argument_roles=["s", "p", "flags"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
]

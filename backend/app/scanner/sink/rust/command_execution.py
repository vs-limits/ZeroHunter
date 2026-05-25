"""Rust — Command Execution sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-cmd-std-process-command",
        function="std::process::Command::new(name)",
        call_regex=r"\bCommand\s*::\s*new\s*\(",
        description="std::process::Command::new with dynamic program name.",
        argument_roles=["program"],
        extensions=_RS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-cmd-command-arg-dynamic",
        function="Command.arg / args",
        call_regex=r"\.\s*args?\s*\(",
        description="Adding args from user input.",
        argument_roles=["arg"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-cmd-command-spawn",
        function="Command.spawn / output / status",
        call_regex=r"\.\s*(?:spawn|output|status)\s*\(\s*\)",
        description="Executes the previously configured Command.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-cmd-tokio-command",
        function="tokio::process::Command::new",
        call_regex=r"\btokio\s*::\s*process\s*::\s*Command\s*::\s*new\s*\(",
        description="Async Command construction with dynamic program.",
        argument_roles=["program"],
        extensions=_RS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-cmd-shell-via-sh-c",
        function="Command::new(\"sh\").arg(\"-c\").arg(userInput)",
        call_regex=r"Command\s*::\s*new\s*\(\s*\"(?:sh|bash|cmd|powershell|pwsh)\"\s*\)",
        description="Explicit shell command — args become shell strings.",
        argument_roles=[],
        extensions=_RS,
        severity="critical",
    ),
    SinkRule(
        id="rs-cmd-duct-cmd",
        function="duct::cmd!",
        call_regex=r"\bduct\s*::\s*cmd!\s*\(|\bcmd!\s*\(",
        description="duct cmd! macro with dynamic interpolation.",
        argument_roles=[],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
]

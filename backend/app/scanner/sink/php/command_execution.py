"""PHP — Command Execution sinks (CWE-78)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-cmd-system",
        function="system",
        call_regex=r"\bsystem\s*\(",
        description="Executes an OS command.",
        argument_roles=["command"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-cmd-exec",
        function="exec",
        call_regex=r"\bexec\s*\(",
        description="Executes an OS command and returns last line.",
        argument_roles=["command"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-cmd-shell-exec",
        function="shell_exec",
        call_regex=r"\bshell_exec\s*\(",
        description="Executes a command through the shell and returns full output.",
        argument_roles=["command"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-cmd-passthru",
        function="passthru",
        call_regex=r"\bpasstthru\s*\(|\bpassthru\s*\(",
        description="Executes a command and streams raw output.",
        argument_roles=["command"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-cmd-proc-open",
        function="proc_open",
        call_regex=r"\bproc_open\s*\(",
        description="Starts a process with caller-controlled command and descriptors.",
        argument_roles=["command", "descriptor_spec"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-cmd-popen",
        function="popen",
        call_regex=r"\bpopen\s*\(",
        description="Opens a process pipe via a command string.",
        argument_roles=["command", "mode"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-cmd-backtick",
        function="backtick operator",
        call_regex=r"`[^`]*\$\w",
        description="PHP backtick operator runs a shell command (variable in string).",
        argument_roles=["command"],
        extensions=_PHP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-cmd-pcntl-exec",
        function="pcntl_exec",
        call_regex=r"\bpcntl_exec\s*\(",
        description="Replaces the current process with a new program.",
        argument_roles=["path", "args"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-cmd-mb-send-mail",
        function="mb_send_mail",
        call_regex=r"\bmb_send_mail\s*\(",
        description="mb_send_mail can be abused for command injection via 5th arg.",
        argument_roles=["to", "subject", "body", "headers", "additional_params"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-cmd-mail",
        function="mail (5th arg)",
        call_regex=r"\bmail\s*\(",
        description="mail() 5th parameter is passed to sendmail; injection risk.",
        argument_roles=["to", "subject", "message", "headers", "params"],
        extensions=_PHP,
        severity="high",
    ),
]

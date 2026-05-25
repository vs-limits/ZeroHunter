"""JavaScript / Node.js — Command Execution sinks (CWE-78)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-cmd-child-process-exec",
        function="child_process.exec",
        call_regex=r"\bchild_process\s*\.\s*exec\s*\(|\.\s*exec\s*\(\s*[`'\"]",
        description="child_process.exec runs a command via the shell.",
        argument_roles=["command", "options"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-cmd-child-process-execsync",
        function="child_process.execSync",
        call_regex=r"\bexecSync\s*\(",
        description="child_process.execSync — same shell risk, blocking.",
        argument_roles=["command", "options"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-cmd-child-process-execfile",
        function="child_process.execFile",
        call_regex=r"\bexecFile(?:Sync)?\s*\(",
        description="execFile runs a binary; argv injection possible if args come from user.",
        argument_roles=["file", "args", "options"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-cmd-child-process-spawn",
        function="child_process.spawn (shell:true)",
        call_regex=r"\bspawn(?:Sync)?\s*\(",
        description="spawn becomes RCE when shell:true and command is user-controlled.",
        argument_roles=["command", "args", "options"],
        extensions=_JS,
        severity="high",
        extra_match_regex=[r"shell\s*:\s*true", r"\$\{"],
    ),
    SinkRule(
        id="js-cmd-shelljs-exec",
        function="shelljs.exec",
        call_regex=r"\bshelljs?\s*\.\s*exec\s*\(",
        description="shelljs.exec executes via shell.",
        argument_roles=["command"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-cmd-execa",
        function="execa(command)",
        call_regex=r"\bexeca(?:Sync|Node)?\s*\(",
        description="execa() spawn — flagged when first arg interpolates user data.",
        argument_roles=["command", "args"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-cmd-vm-runinnewcontext",
        function="vm.runInNewContext / runInThisContext",
        call_regex=r"\bvm\s*\.\s*runIn(?:NewContext|ThisContext|Context)\s*\(",
        description="Node's vm module evaluates arbitrary JS, often weaponised as RCE.",
        argument_roles=["code"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-cmd-eval",
        function="eval(...)",
        call_regex=r"\beval\s*\(",
        description="eval executes JS string (also under command_execution as RCE).",
        argument_roles=["code"],
        extensions=_JS,
        severity="critical",
    ),
]

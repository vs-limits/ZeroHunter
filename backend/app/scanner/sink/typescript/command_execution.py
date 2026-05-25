"""TypeScript — Command Execution sinks unique to Deno / Bun runtimes."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_TS = [".ts", ".tsx"]

RULES = [
    SinkRule(
        id="ts-cmd-deno-command",
        function="new Deno.Command(cmd, opts)",
        call_regex=r"\bnew\s+Deno\.\s*Command\s*\(",
        description="Deno.Command spawns subprocess with attacker-controlled cmd / args.",
        argument_roles=["command", "options"],
        extensions=_TS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="ts-cmd-deno-run-legacy",
        function="Deno.run({cmd:[...]})",
        call_regex=r"\bDeno\.\s*run\s*\(",
        description="Deprecated Deno.run — same risks as Deno.Command.",
        argument_roles=["options"],
        extensions=_TS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="ts-cmd-bun-spawn",
        function="Bun.spawn / Bun.spawnSync",
        call_regex=r"\bBun\.\s*spawn(?:Sync)?\s*\(",
        description="Bun.spawn runs subprocess (`shell:true` makes it RCE).",
        argument_roles=["cmd", "options"],
        extensions=_TS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="ts-cmd-bun-shell",
        function="Bun shell `$`",
        call_regex=r"\$`[^`]*\$\{",
        description="Bun shell template-tag with interpolation — direct command injection.",
        argument_roles=[],
        extensions=_TS,
        severity="critical",
    ),
]

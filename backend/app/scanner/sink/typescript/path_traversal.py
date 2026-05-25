"""TypeScript — Deno/Bun specific Path Traversal sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "path_traversal"

_TS = [".ts", ".tsx"]

RULES = [
    SinkRule(
        id="ts-path-deno-readfile",
        function="Deno.readFile / readTextFile",
        call_regex=r"\bDeno\.\s*readTextFile|\bDeno\.\s*readFile",
        description="Deno read* APIs with dynamic path.",
        argument_roles=["path"],
        extensions=_TS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="ts-path-deno-writefile",
        function="Deno.writeFile / writeTextFile",
        call_regex=r"\bDeno\.\s*write(?:Text)?File\b",
        description="Deno write* with dynamic path.",
        argument_roles=["path", "data"],
        extensions=_TS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="ts-path-deno-remove",
        function="Deno.remove",
        call_regex=r"\bDeno\.\s*remove(?:Sync)?\s*\(",
        description="Deno.remove with dynamic path can delete arbitrary file.",
        argument_roles=["path", "options"],
        extensions=_TS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="ts-path-bun-file",
        function="Bun.file(path)",
        call_regex=r"\bBun\.\s*file\s*\(",
        description="Bun.file references arbitrary file by path.",
        argument_roles=["path"],
        extensions=_TS,
        severity="high",
        require_dynamic=True,
    ),
]

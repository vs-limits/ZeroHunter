"""TypeScript — Deno/Bun specific SSRF sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssrf"

_TS = [".ts", ".tsx"]

RULES = [
    SinkRule(
        id="ts-ssrf-deno-fetch",
        function="fetch(url) in Deno",
        call_regex=r"\bfetch\s*\(",
        description="Deno fetch with --allow-net=* allows arbitrary outbound.",
        argument_roles=["resource"],
        extensions=_TS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="ts-ssrf-deno-connect",
        function="Deno.connect / Deno.connectTls",
        call_regex=r"\bDeno\.\s*connect(?:Tls)?\s*\(",
        description="Low-level socket connect to user host:port.",
        argument_roles=["options"],
        extensions=_TS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="ts-ssrf-bun-fetch",
        function="Bun.fetch / fetch",
        call_regex=r"\bBun\.\s*fetch\s*\(",
        description="Bun fetch with dynamic URL.",
        argument_roles=["url"],
        extensions=_TS,
        severity="high",
        require_dynamic=True,
    ),
]

"""TypeScript — Deserialization sinks specific to TS toolchains."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_TS = [".ts", ".tsx"]

RULES = [
    SinkRule(
        id="ts-deser-class-transformer-plain-to-class",
        function="class-transformer plainToInstance",
        call_regex=r"\bplainTo(?:Instance|Class)\s*\(",
        description="class-transformer with enableImplicitConversion may instantiate unexpected types.",
        argument_roles=["cls", "plain"],
        extensions=_TS,
        severity="medium",
    ),
    SinkRule(
        id="ts-deser-yaml-load",
        function="yaml.load(string)",
        call_regex=r"\byaml\s*\.\s*load\s*\(",
        description="js-yaml load (TS imports) accepting !!js/function tag pre v4.",
        argument_roles=["src"],
        extensions=_TS,
        severity="high",
    ),
    SinkRule(
        id="ts-deser-protobuf-decode-unknown",
        function="proto.decode(unknown bytes)",
        call_regex=r"\.\s*decode\s*\(\s*(?:Buffer|Uint8Array|new\s+Uint8Array)",
        description="Proto decode of untrusted bytes — verify schema strictness.",
        argument_roles=["reader"],
        extensions=_TS,
        severity="medium",
    ),
]

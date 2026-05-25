"""Rust — Insecure Deserialization sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-deser-bincode-deserialize",
        function="bincode::deserialize / deserialize_from",
        call_regex=r"\bbincode\s*::\s*(?:deserialize|deserialize_from|deserialize_in_place)\s*\(",
        description="bincode deserialise without size limits — DoS / type-pivot.",
        argument_roles=["bytes"],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-deser-serde-yaml-from-str",
        function="serde_yaml::from_str / from_slice / from_reader",
        call_regex=r"\bserde_yaml\s*::\s*from_(?:str|slice|reader|value)\s*\(",
        description="serde_yaml can construct attacker-chosen variants via tags.",
        argument_roles=["s"],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-deser-rmp-serde",
        function="rmp_serde::from_slice / from_read",
        call_regex=r"\brmp_serde\s*::\s*from_(?:slice|read|read_ref)\s*\(",
        description="MessagePack deserialise of untrusted bytes.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-deser-pickle-from-reader",
        function="serde-pickle from_reader",
        call_regex=r"\bserde_pickle\s*::\s*from_reader\s*\(",
        description="Pickle deserialise — same RCE class as Python pickle.",
        argument_roles=[],
        extensions=_RS,
        severity="critical",
    ),
    SinkRule(
        id="rs-deser-toml-from-str",
        function="toml::from_str(userInput)",
        call_regex=r"\btoml\s*::\s*from_str\s*\(",
        description="toml::from_str on user input — DoS / type confusion.",
        argument_roles=["s"],
        extensions=_RS,
        severity="low",
    ),
]

"""Go — Insecure Deserialization sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-deser-gob-decode",
        function="gob.NewDecoder(r).Decode",
        call_regex=r"\bgob\s*\.\s*NewDecoder\s*\(",
        description="encoding/gob decoder on untrusted stream — type pivot RCE-ish risk.",
        argument_roles=["r"],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-deser-json-unmarshal-interface",
        function="json.Unmarshal into interface{}",
        call_regex=r"\bjson\s*\.\s*Unmarshal\s*\(",
        description="Unmarshalling into map[string]interface{} bypasses schema validation.",
        argument_roles=["data", "v"],
        extensions=_GO,
        severity="low",
    ),
    SinkRule(
        id="go-deser-yaml-unmarshal",
        function="yaml.Unmarshal(strict=false)",
        call_regex=r"\byaml\s*\.\s*(?:Unmarshal|UnmarshalStrict)\s*\(",
        description="go-yaml Unmarshal on user YAML; can reach unexpected types via tags.",
        argument_roles=["in", "out"],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-deser-msgpack-decode",
        function="msgpack.NewDecoder().Decode",
        call_regex=r"\bmsgpack\s*\.\s*(?:NewDecoder|Unmarshal)\s*\(",
        description="msgpack decode of untrusted bytes.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-deser-xml-unmarshal",
        function="xml.Unmarshal",
        call_regex=r"\bxml\s*\.\s*(?:Unmarshal|NewDecoder)\s*\(",
        description="encoding/xml decoder — entity expansion risks on Strict=false.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
]

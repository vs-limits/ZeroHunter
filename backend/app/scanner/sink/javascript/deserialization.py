"""JavaScript / Node.js — Insecure Deserialization sinks (CWE-502)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-deser-node-serialize-unserialize",
        function="node-serialize.unserialize",
        call_regex=r"\b(?:node[-_]serialize|serialize)\s*\.\s*unserialize\s*\(",
        description="node-serialize unserialize() is known RCE.",
        argument_roles=["data"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-deser-funcster",
        function="funcster.deepDeserialize",
        call_regex=r"\bfuncster\s*\.\s*deepDeserialize\s*\(",
        description="funcster deepDeserialize reconstructs functions from data.",
        argument_roles=["data"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-deser-yaml-load",
        function="js-yaml load (non-SAFE)",
        call_regex=r"\byaml\s*\.\s*load\s*\(",
        description="js-yaml.load (pre-4) used !!js/function tag; flag if not using safeLoad.",
        argument_roles=["src", "options"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-deser-json-parse-eval",
        function="JSON.parse(...) with reviver eval",
        call_regex=r"\bJSON\s*\.\s*parse\s*\([^)]*eval",
        description="Reviver function calling eval re-introduces RCE.",
        argument_roles=["text", "reviver"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-deser-bson-deserialize",
        function="bson.deserialize",
        call_regex=r"\bbson\s*\.\s*deserialize\s*\(",
        description="BSON.deserialize trusts attacker-controlled types.",
        argument_roles=["buffer"],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-deser-uneval",
        function="uneval(value)",
        call_regex=r"\buneval\s*\(",
        description="SpiderMonkey uneval — reverse of eval, used in toolchains.",
        argument_roles=["value"],
        extensions=_JS,
        severity="high",
    ),
]

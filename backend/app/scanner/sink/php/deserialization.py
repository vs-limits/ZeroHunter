"""PHP — Deserialization sinks (CWE-502)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-deser-unserialize",
        function="unserialize",
        call_regex=r"\bunserialize\s*\(",
        description="Deserializes PHP data and may instantiate arbitrary objects.",
        argument_roles=["serialized_value", "options"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-deser-yaml-parse",
        function="yaml_parse / Symfony Yaml::parse",
        call_regex=r"\b(?:yaml_parse|Yaml\s*::\s*parse)\s*\(",
        description="YAML parser may instantiate PHP objects via tags (Symfony Yaml).",
        argument_roles=["yaml_text"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-deser-phar-stream",
        function="phar:// wrapper",
        call_regex=r"['\"]phar://",
        description="phar:// stream wrapper triggers metadata unserialize on file ops.",
        argument_roles=["path"],
        extensions=_PHP,
        severity="high",
    ),
]

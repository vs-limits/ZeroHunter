"""Java — Insecure Deserialization sinks (CWE-502)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "deserialization"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-deser-objectinputstream-readobject",
        function="ObjectInputStream.readObject",
        call_regex=r"\.\s*readObject\s*\(",
        description="readObject() on untrusted stream is classic Java deserialization RCE.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-deser-objectinputstream-readunshared",
        function="ObjectInputStream.readUnshared",
        call_regex=r"\.\s*readUnshared\s*\(",
        description="readUnshared() — same risk profile as readObject().",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-deser-xmldecoder-readobject",
        function="XMLDecoder.readObject",
        call_regex=r"\bXMLDecoder\b[\s\S]{0,40}\.\s*readObject\s*\(",
        description="java.beans.XMLDecoder is RCE-by-design on untrusted XML.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-deser-jackson-enabledefaulttyping",
        function="ObjectMapper.enableDefaultTyping / activateDefaultTyping",
        call_regex=r"\.\s*(?:enableDefaultTyping|activateDefaultTyping)\s*\(",
        description="Polymorphic typing in Jackson enables gadget-class deserialization.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-deser-jackson-readvalue",
        function="ObjectMapper.readValue with polymorphic type",
        call_regex=r"\.\s*readValue\s*\(",
        description="Jackson readValue — flag for review of @JsonTypeInfo handling.",
        argument_roles=["src", "valueType"],
        extensions=_JAVA,
        severity="medium",
    ),
    SinkRule(
        id="java-deser-fastjson-parse",
        function="JSON.parseObject / parse (Fastjson)",
        call_regex=r"\bJSON\s*\.\s*(?:parse|parseObject|parseArray)\s*\(",
        description="Fastjson with autoType enabled allows gadget RCE.",
        argument_roles=["text", "clazz"],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-deser-snakeyaml-load",
        function="Yaml.load(InputStream)",
        call_regex=r"\bYaml\s*\(\s*\)[\s\S]{0,40}\.\s*load\s*\(|\bnew\s+Yaml\s*\(\s*\)\s*\.\s*load\s*\(",
        description="SnakeYAML default constructor enables type tags = RCE.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-deser-xstream-fromxml",
        function="XStream.fromXML",
        call_regex=r"\bXStream\b[\s\S]{0,40}\.\s*fromXML\s*\(",
        description="XStream fromXML without strict typing has historic RCE chains.",
        argument_roles=["xml"],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-deser-kryo-read",
        function="Kryo.readClassAndObject / readObject",
        call_regex=r"\bkryo\s*\.\s*(?:readClassAndObject|readObject|readObjectOrNull)\s*\(",
        description="Kryo readClassAndObject deserializes by class — RCE on gadget classes.",
        argument_roles=["input"],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-deser-hessian-readobject",
        function="HessianInput / Hessian2Input.readObject",
        call_regex=r"\bHessian2?(?:Input|StreamingInput)\b[\s\S]{0,40}\.\s*readObject\s*\(",
        description="Hessian deserialization RCE chains in CVE-2021-43113 etc.",
        argument_roles=[],
        extensions=_JAVA,
        severity="critical",
    ),
]

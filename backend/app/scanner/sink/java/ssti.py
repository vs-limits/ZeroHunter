"""Java — SSTI sinks (Freemarker, Velocity, Thymeleaf, Pebble)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssti"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-ssti-freemarker-process",
        function="freemarker.Template.process",
        call_regex=r"\bnew\s+Template\s*\(|\.\s*process\s*\(\s*[\w]+,\s*new\s+StringWriter",
        description="Freemarker template constructed from user input.",
        argument_roles=["name", "reader", "config"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssti-velocity-evaluate",
        function="Velocity.evaluate / mergeTemplate",
        call_regex=r"\bVelocity\s*\.\s*(?:evaluate|mergeTemplate)\s*\(",
        description="Velocity evaluate / mergeTemplate with user template.",
        argument_roles=["context", "writer", "logTag", "instring"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssti-thymeleaf-process",
        function="TemplateEngine.process(rawString)",
        call_regex=r"\.\s*process\s*\(",
        description="Thymeleaf TemplateEngine.process — user-controlled template = RCE.",
        argument_roles=["template", "context"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssti-pebble-getliteral",
        function="PebbleTemplate getLiteralTemplate",
        call_regex=r"\bgetLiteralTemplate\s*\(",
        description="Pebble template from user string.",
        argument_roles=["template"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssti-groovy-templateengine",
        function="GroovyTemplate.createTemplate",
        call_regex=r"\bcreateTemplate\s*\(",
        description="Groovy SimpleTemplateEngine / GStringTemplateEngine — RCE on dynamic source.",
        argument_roles=["text"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
]

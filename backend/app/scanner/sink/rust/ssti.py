"""Rust — SSTI sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssti"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-ssti-tera-one-off",
        function="tera::Tera::one_off(template, ctx, autoescape)",
        call_regex=r"\bTera\s*::\s*one_off\s*\(",
        description="Tera one_off with user-controlled template string.",
        argument_roles=["input", "context", "autoescape"],
        extensions=_RS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-ssti-handlebars-render-template",
        function="Handlebars::render_template",
        call_regex=r"\.\s*render_template(?:_with_context)?\s*\(",
        description="Handlebars render_template compiles caller-supplied template.",
        argument_roles=["template", "data"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-ssti-minijinja-from-source",
        function="minijinja::Environment.add_template",
        call_regex=r"\.\s*add_template\s*\(",
        description="minijinja add_template with dynamic source.",
        argument_roles=["name", "source"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
]

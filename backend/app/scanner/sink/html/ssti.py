"""HTML/template — SSTI surface flags (template strings reaching the engine)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssti"

_TPL = [".html", ".htm", ".xhtml", ".jinja", ".jinja2", ".j2", ".tpl", ".tmpl", ".ejs", ".hbs", ".mustache", ".tera", ".twig", ".liquid", ".njk"]

RULES = [
    # NOTE: the previous "every {{ var }}" rule was dropped — it fires on
    # every legitimate template variable and drowns the report. Real SSTI
    # candidates come from raw/unsafe filters (see xss.py) or include tags.
    SinkRule(
        id="html-ssti-twig-template-from",
        function="{% include user_string %}",
        # Only flag dynamic include targets: bare variable or expression,
        # never a string-literal path.
        call_regex=r"\{%\s*include\s+[a-zA-Z_]",
        description="include tag with non-literal — possible template injection.",
        argument_roles=[],
        extensions=_TPL,
        severity="medium",
    ),
    SinkRule(
        id="html-ssti-handlebars-partial-dyn",
        function="{{> partialName }} dynamic",
        call_regex=r"\{\{>\s*\w+\s*\}\}",
        description="Handlebars partial name from dynamic source.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
]

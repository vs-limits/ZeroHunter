"""Python — SSTI / Server-Side Template Injection sinks (CWE-1336)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssti"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-ssti-jinja2-template-from-string",
        function="jinja2.Template / Environment.from_string",
        call_regex=r"\b(?:Template|from_string)\s*\(",
        description="Jinja2 template compiled from a user-controlled string — RCE class issue.",
        argument_roles=["source"],
        extensions=_PY,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssti-render-template-string",
        function="flask.render_template_string",
        call_regex=r"\brender_template_string\s*\(",
        description="render_template_string compiles its first arg with Jinja2 — SSTI on user input.",
        argument_roles=["source"],
        extensions=_PY,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssti-mako-template",
        function="mako.template.Template",
        call_regex=r"\bTemplate\s*\(",
        description="Mako Template() compiled from dynamic source allows arbitrary Python.",
        argument_roles=["text"],
        extensions=_PY,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssti-django-engine-from-string",
        function="django.template.Engine.from_string",
        call_regex=r"\bEngine[^)]*\.\s*from_string\s*\(",
        description="Django Engine.from_string with user-controlled template.",
        argument_roles=["template_code"],
        extensions=_PY,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssti-django-template",
        function="django.template.Template",
        call_regex=r"\bTemplate\s*\(\s*[a-zA-Z_]",
        description="Django Template() built from user input.",
        argument_roles=["template_string"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssti-chameleon",
        function="chameleon.PageTemplate",
        call_regex=r"\bPageTemplate\s*\(",
        description="Chameleon PageTemplate compiled from dynamic source.",
        argument_roles=["body"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssti-tornado-template",
        function="tornado.template.Template",
        call_regex=r"\btornado\.template\.\s*Template\s*\(",
        description="Tornado Template compiled from dynamic source.",
        argument_roles=["template_string"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
]

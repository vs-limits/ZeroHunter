"""Python — XSS sinks (CWE-79).

Covers Flask/Django/FastAPI/Jinja2/Bottle/Tornado response builders
and HTML-bypass calls such as ``mark_safe`` / ``|safe``.
"""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xss"

_PY = [".py", ".pyi", ".pyw"]
_TEMPLATES = [".html", ".htm", ".jinja", ".jinja2", ".j2", ".tpl"]

RULES = [
    SinkRule(
        id="py-xss-flask-make-response",
        function="flask.make_response / Response(html)",
        call_regex=r"\b(?:make_response|Response)\s*\(",
        description="Flask response built from a raw HTML string that may include user input.",
        argument_roles=["body"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-xss-django-httpresponse",
        function="django.http.HttpResponse",
        call_regex=r"\bHttpResponse\s*\(",
        description="HttpResponse with concatenated/formatted HTML bypasses template escaping.",
        argument_roles=["content"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-xss-django-mark-safe",
        function="django.utils.safestring.mark_safe",
        call_regex=r"\bmark_safe\s*\(",
        description="mark_safe disables Django auto-escaping for the wrapped value.",
        argument_roles=["s"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-xss-django-format-html",
        function="django.utils.html.format_html",
        call_regex=r"\bformat_html\s*\(",
        description="format_html with already-marked-safe substitutions can re-introduce XSS.",
        argument_roles=["format", "args"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-xss-jinja2-markup",
        function="jinja2.Markup / markupsafe.Markup",
        call_regex=r"\bMarkup\s*\(",
        description="Markup(...) tells Jinja2 the value is already-escaped HTML.",
        argument_roles=["html"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-xss-jinja2-autoescape-off",
        function="Environment(autoescape=False)",
        call_regex=r"autoescape\s*=\s*False",
        description="Jinja2 environment with autoescape disabled.",
        argument_roles=["autoescape"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-xss-template-safe-filter",
        function="template |safe filter",
        call_regex=r"\|\s*safe\b",
        description="Django/Jinja2 |safe filter prints a value as raw HTML.",
        argument_roles=["expression"],
        extensions=_TEMPLATES + _PY,
        severity="high",
    ),
    SinkRule(
        id="py-xss-fastapi-htmlresponse",
        function="fastapi.responses.HTMLResponse",
        call_regex=r"\bHTMLResponse\s*\(",
        description="Returning user-controlled string via HTMLResponse.",
        argument_roles=["content"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-xss-render-string",
        function="render_template_string",
        call_regex=r"\brender_template_string\s*\(",
        description="render_template_string with user input is both XSS and SSTI.",
        argument_roles=["source"],
        extensions=_PY,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-xss-tornado-write",
        function="tornado RequestHandler.write",
        call_regex=r"self\.write\s*\(",
        description="Tornado RequestHandler.write() with raw string.",
        argument_roles=["chunk"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-xss-bottle-template",
        function="bottle.template / SimpleTemplate",
        call_regex=r"\btemplate\s*\(",
        description="bottle.template with user-controlled template string.",
        argument_roles=["template"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
]

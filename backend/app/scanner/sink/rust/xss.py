"""Rust — XSS sinks in web frameworks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xss"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-xss-actix-htmlresponse",
        function="HttpResponse::Ok().body(html)",
        call_regex=r"\bHttpResponse\s*::\s*Ok\s*\(\s*\)\s*\.\s*(?:body|content_type)\s*\(",
        description="Actix HttpResponse body of concatenated HTML.",
        argument_roles=["body"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-xss-axum-html",
        function="axum::response::Html(value)",
        call_regex=r"\bHtml\s*\(",
        description="axum Html(...) wrapper marks value as HTML response.",
        argument_roles=["value"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-xss-askama-escape-off",
        function="askama escape=\"none\" attribute",
        call_regex=r"escape\s*=\s*\"none\"",
        description="askama template with escape=\"none\".",
        argument_roles=[],
        extensions=[".rs", ".html"],
        severity="medium",
    ),
    SinkRule(
        id="rs-xss-tera-safe-filter",
        function="tera {{ value | safe }}",
        call_regex=r"\|\s*safe\b",
        description="Tera safe filter bypasses escaping.",
        argument_roles=[],
        extensions=[".tera", ".html", ".rs"],
        severity="high",
    ),
    SinkRule(
        id="rs-xss-handlebars-triple",
        function="handlebars {{{value}}}",
        call_regex=r"\{\{\{[^}]+\}\}\}",
        description="Handlebars triple-stache prints raw HTML.",
        argument_roles=[],
        extensions=[".hbs", ".html", ".rs"],
        severity="high",
    ),
]

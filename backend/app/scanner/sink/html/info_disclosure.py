"""HTML — Information Disclosure patterns (comments, debug info, source maps)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_HTML = [".html", ".htm", ".xhtml", ".vue", ".svelte"]
_TPL = _HTML + [".jinja", ".jinja2", ".j2", ".tpl", ".tmpl", ".ejs", ".hbs", ".mustache", ".tera", ".twig", ".liquid", ".njk"]

RULES = [
    SinkRule(
        id="html-info-todo-comment",
        function="<!-- TODO / FIXME / DEBUG comments -->",
        call_regex=r"<!--[\s\S]{0,200}(?:TODO|FIXME|HACK|XXX|DEBUG|password|secret|token|api[_-]?key)",
        description="HTML comments that may leak internal info or credentials.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
    SinkRule(
        id="html-info-error-stack-render",
        function="rendered Python/Django traceback inside HTML",
        call_regex=r"Traceback\s*\(most\s+recent\s+call\s+last\)",
        description="Traceback text rendered in HTML page.",
        argument_roles=[],
        extensions=_TPL,
        severity="high",
    ),
    SinkRule(
        id="html-info-sourcemap-link",
        function="//# sourceMappingURL=app.js.map",
        call_regex=r"//#\s*sourceMappingURL\s*=",
        description="Source map reference exposes original source paths.",
        argument_roles=[],
        extensions=[".js", ".html", ".css"],
        severity="low",
    ),
    SinkRule(
        id="html-info-internal-ip-link",
        function="internal/private IP hardcoded in href",
        call_regex=r"\bhref\s*=\s*[\"']https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.0\.0\.1|localhost)",
        description="Internal/private host leaked in href/src.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
    SinkRule(
        id="html-info-config-token-attr",
        function="data-* attribute containing token",
        call_regex=r"\bdata-(?:token|api[_-]?key|secret|password|jwt|session)\s*=\s*[\"']",
        description="Sensitive data persisted via data-* attributes is shipped to the browser.",
        argument_roles=[],
        extensions=_TPL,
        severity="medium",
    ),
]

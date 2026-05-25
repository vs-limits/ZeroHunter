"""HTML — CSRF-relevant patterns (forms missing token, target=\"_top\" auto-submit, etc.)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "csrf"

_HTML = [".html", ".htm", ".xhtml", ".vue", ".svelte"]
_TPL = _HTML + [".jinja", ".jinja2", ".j2", ".tpl", ".tmpl", ".ejs", ".hbs", ".mustache", ".tera", ".twig", ".liquid", ".njk", ".blade.php"]

RULES = [
    SinkRule(
        id="html-csrf-form-no-token",
        function="<form method=\"post\"> without CSRF token field",
        call_regex=r"<form\b[^>]*\bmethod\s*=\s*[\"']post[\"'][^>]*>",
        description="POST form — review whether CSRF token hidden input is rendered inside.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
    SinkRule(
        id="html-csrf-autosubmit-form",
        function="onload auto-submit form",
        call_regex=r"<form\b[^>]*\bonload\s*=\s*[\"'][^\"']*submit",
        description="Form auto-submits on load — abused in CSRF PoC pages.",
        argument_roles=[],
        extensions=_TPL,
        severity="medium",
    ),
    SinkRule(
        id="html-csrf-img-state-changing-url",
        function="<img src=\"...action=delete...\"> in user content",
        call_regex=r"<img\b[^>]*src\s*=\s*[\"'][^\"']*(?:action|delete|logout|change|update)",
        description="Image src looks state-changing — CSRF when reflected user content.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
    SinkRule(
        id="html-csrf-formaction-userdata",
        function="<button formaction=\"${user}\">",
        call_regex=r"\bformaction\s*=\s*[\"']",
        description="formaction attribute overrides form's action — verify origin.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
]

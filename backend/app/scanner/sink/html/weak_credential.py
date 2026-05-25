"""HTML — Hardcoded credentials embedded in templates / static pages."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "weak_credential"

_HTML = [".html", ".htm", ".xhtml", ".vue", ".svelte"]
_TPL = _HTML + [".jinja", ".jinja2", ".j2", ".tpl", ".tmpl", ".ejs", ".hbs", ".mustache", ".tera", ".twig", ".liquid", ".njk"]

RULES = [
    SinkRule(
        id="html-cred-input-value-password",
        function="<input type=\"password\" value=\"...\">",
        call_regex=r"<input\b[^>]*type\s*=\s*[\"']password[\"'][^>]*value\s*=\s*[\"'][^\"']+[\"']",
        description="Password input pre-populated with literal value.",
        argument_roles=[],
        extensions=_HTML,
        severity="high",
    ),
    SinkRule(
        id="html-cred-comment-password",
        function="<!-- password: ... --> embed",
        call_regex=r"<!--[\s\S]{0,200}(?:password|secret|api[_-]?key|token)\s*[:=]",
        description="Credential-like value embedded in HTML comment.",
        argument_roles=[],
        extensions=_TPL,
        severity="critical",
    ),
    SinkRule(
        id="html-cred-meta-token",
        function="<meta name=\"csrf-token\" content=\"...\"> (token leak)",
        call_regex=r"<meta\b[^>]*name\s*=\s*[\"'](?:api[_-]?key|secret|token|jwt|bearer)[\"']",
        description="Sensitive token embedded in <meta>.",
        argument_roles=[],
        extensions=_TPL,
        severity="high",
    ),
    SinkRule(
        id="html-cred-pem-block",
        function="PEM private key in HTML",
        call_regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="PEM private key copy-pasted into HTML/template.",
        argument_roles=[],
        extensions=_TPL,
        severity="critical",
    ),
]

"""HTML — Auth Bypass / clickjacking-class flags."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "auth_bypass"

_HTML = [".html", ".htm", ".xhtml", ".vue", ".svelte"]
_TPL = _HTML + [".jinja", ".jinja2", ".j2", ".tpl", ".tmpl", ".ejs", ".hbs", ".mustache", ".tera", ".twig", ".liquid", ".njk"]

RULES = [
    SinkRule(
        id="html-auth-iframe-no-sandbox",
        function="<iframe ...> without sandbox attr",
        # rg's Rust regex has no negative lookahead. We match every <iframe>
        # and let Auditor verify the sandbox attribute presence downstream.
        call_regex=r"<iframe\b",
        description="iframe — verify sandbox attribute is set.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
    SinkRule(
        id="html-auth-meta-noframe-missing",
        function="page without X-Frame-Options meta tag",
        call_regex=r"<meta\s+http-equiv\s*=\s*[\"']X-Frame-Options[\"']",
        description="Track whether X-Frame-Options meta is present (its absence is the issue).",
        argument_roles=[],
        extensions=_HTML,
        severity="low",
    ),
    SinkRule(
        id="html-auth-form-cleartext-password",
        function="<form ... action=\"http://...\"> with password input",
        call_regex=r"<form\b[^>]*action\s*=\s*[\"']http://",
        description="Password form submitting over HTTP — credential exposure.",
        argument_roles=[],
        extensions=_HTML,
        severity="high",
    ),
    SinkRule(
        id="html-auth-autocomplete-on-password",
        function="<input type=password autocomplete=\"on\">",
        call_regex=r"<input\b[^>]*type\s*=\s*[\"']password[\"'][^>]*autocomplete\s*=\s*[\"']on[\"']",
        description="Allowing autocomplete on password field on shared devices.",
        argument_roles=[],
        extensions=_HTML,
        severity="low",
    ),
]

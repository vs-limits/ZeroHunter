"""HTML — File Upload misconfiguration flags."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_HTML = [".html", ".htm", ".xhtml", ".vue", ".svelte"]
_TPL = _HTML + [".jinja", ".jinja2", ".j2", ".tpl", ".tmpl", ".ejs", ".hbs", ".mustache", ".tera", ".twig", ".liquid", ".njk"]

RULES = [
    SinkRule(
        id="html-upload-input-no-accept",
        function="<input type=\"file\"> without accept attribute",
        call_regex=r"<input\b[^>]*type\s*=\s*[\"']file[\"']",
        description="File input without accept attribute — server must still verify type.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
    SinkRule(
        id="html-upload-form-enctype-missing",
        function="<form ... method=\"post\"> with file but no multipart enctype",
        # rg's Rust regex has no negative lookahead. Match every POST form
        # and let Auditor decide whether the enctype is present.
        call_regex=r"<form\b[^>]*\bmethod\s*=\s*[\"']post[\"']",
        description="POST form — verify multipart enctype when file inputs are present.",
        argument_roles=[],
        extensions=_TPL,
        severity="low",
    ),
]

"""JavaScript / Node.js — SSTI sinks (CWE-1336)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssti"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-ssti-handlebars-compile",
        function="Handlebars.compile(template)",
        call_regex=r"\bHandlebars\s*\.\s*compile\s*\(",
        description="Compiling a user-controlled Handlebars template enables RCE on some versions.",
        argument_roles=["source"],
        extensions=_JS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-ssti-pug-compile",
        function="pug.compile / render(string)",
        call_regex=r"\bpug\s*\.\s*(?:compile|render|renderFile)\s*\(",
        description="Pug compile/render with dynamic template string is RCE.",
        argument_roles=["source"],
        extensions=_JS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-ssti-ejs-render",
        function="ejs.render(template, data)",
        call_regex=r"\bejs\s*\.\s*(?:render|compile|renderFile)\s*\(",
        description="EJS render with template from user input.",
        argument_roles=["template", "data"],
        extensions=_JS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-ssti-doT-template",
        function="doT.template(tpl, opts)",
        call_regex=r"\bdoT\s*\.\s*template\s*\(",
        description="doT.template generates a function from a string template.",
        argument_roles=["tmpl"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-ssti-nunjucks-renderString",
        function="nunjucks.renderString",
        call_regex=r"\bnunjucks\s*\.\s*renderString\s*\(",
        description="nunjucks.renderString compiles caller-supplied source.",
        argument_roles=["src", "ctx"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-ssti-marko-load-string",
        function="marko.load(string)",
        call_regex=r"\bmarko\s*\.\s*load\s*\(",
        description="marko.load with caller-controlled string.",
        argument_roles=["template"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
]

"""Go — XSS sinks (CWE-79)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xss"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-xss-text-template",
        function="text/template.Execute(html-context)",
        call_regex=r"text/template\b",
        description="text/template does NOT escape; use html/template for HTML output.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-xss-template-html-cast",
        function="template.HTML(value)",
        call_regex=r"\btemplate\s*\.\s*HTML\s*\(",
        description="template.HTML cast marks value as already-safe HTML.",
        argument_roles=["s"],
        extensions=_GO,
        severity="critical",
    ),
    SinkRule(
        id="go-xss-template-js",
        function="template.JS / JSStr",
        call_regex=r"\btemplate\s*\.\s*(?:JS|JSStr)\s*\(",
        description="template.JS marks string as safe JS content.",
        argument_roles=["s"],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-xss-template-url",
        function="template.URL",
        call_regex=r"\btemplate\s*\.\s*URL\s*\(",
        description="template.URL bypasses URL filter (javascript:).",
        argument_roles=["s"],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-xss-fprintf-response",
        function="fmt.Fprintf(w, ...)",
        call_regex=r"\bfmt\s*\.\s*Fprintf?\s*\(\s*w\b",
        description="Writing formatted HTML to ResponseWriter without escaping.",
        argument_roles=["w", "format", "args"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-xss-w-write-bytes",
        function="w.Write([]byte(htmlString))",
        call_regex=r"w\s*\.\s*Write\s*\(\s*\[\]byte\s*\(",
        description="ResponseWriter.Write of raw HTML constructed via concatenation.",
        argument_roles=["p"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-xss-gin-html-string",
        function="c.String(200, '<html>...')",
        call_regex=r"\.\s*String\s*\(\s*\d+\s*,\s*\"[^\"]*<",
        description="Gin c.String returning HTML — confirm escape.",
        argument_roles=["code", "format", "values"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

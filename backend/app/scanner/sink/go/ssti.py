"""Go — SSTI sinks. text/template + html/template Parse on user input."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssti"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-ssti-template-parse",
        function="template.New(...).Parse(userInput)",
        call_regex=r"\.\s*Parse\s*\(",
        description="text/template or html/template Parse with caller-supplied source.",
        argument_roles=["text"],
        extensions=_GO,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ssti-template-parseglob",
        function="template.ParseGlob with dynamic pattern",
        call_regex=r"\.\s*ParseGlob\s*\(",
        description="ParseGlob with dynamic pattern loads arbitrary template files.",
        argument_roles=["pattern"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ssti-pongo2-fromstring",
        function="pongo2.FromString(template)",
        call_regex=r"\bpongo2\s*\.\s*FromString\s*\(",
        description="Pongo2 template compiled from user input.",
        argument_roles=["template"],
        extensions=_GO,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ssti-jet-loaderload",
        function="jet template loaded from string",
        call_regex=r"\bjet\s*\.\s*(?:NewSet|HTMLSet)\b",
        description="CloudyKit jet template loader — verify source.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
]

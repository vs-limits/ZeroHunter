"""Go — Code Execution / Reflection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "code_execution"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-code-plugin-open",
        function="plugin.Open(path).Lookup(symbol)",
        call_regex=r"\bplugin\s*\.\s*Open\s*\(",
        description="Loading external .so plugin — full RCE if path is user-controlled.",
        argument_roles=["path"],
        extensions=_GO,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-code-reflect-call",
        function="reflect.Value.Call",
        call_regex=r"\.\s*Call\s*\(",
        description="reflect.Value.Call invoking user-selected method.",
        argument_roles=["in"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-code-yaegi-eval",
        function="yaegi/Interp.Eval",
        call_regex=r"\bInterp\b[\s\S]{0,40}\.\s*Eval\s*\(",
        description="yaegi (Go interpreter) Eval with user input.",
        argument_roles=["src"],
        extensions=_GO,
        severity="critical",
    ),
    SinkRule(
        id="go-code-otto-run",
        function="otto.Run(jsCode)",
        call_regex=r"\botto\b[\s\S]{0,40}\.\s*Run\s*\(",
        description="otto JS interpreter executing user JS.",
        argument_roles=["src"],
        extensions=_GO,
        severity="critical",
    ),
]

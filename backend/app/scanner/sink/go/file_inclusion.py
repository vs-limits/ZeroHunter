"""Go — File / Plugin Inclusion sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_inclusion"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-incl-plugin-open",
        function="plugin.Open(path)",
        call_regex=r"\bplugin\s*\.\s*Open\s*\(",
        description="Loading .so plugin from caller path — full RCE if attacker controlled.",
        argument_roles=["path"],
        extensions=_GO,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-incl-template-parsefiles",
        function="template.ParseFiles(userPath)",
        call_regex=r"\.\s*ParseFiles\s*\(",
        description="ParseFiles loading caller-controlled template path.",
        argument_roles=["filenames"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

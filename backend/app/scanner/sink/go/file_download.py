"""Go — File Download sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_download"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-dl-http-servefile",
        function="http.ServeFile",
        call_regex=r"\bhttp\s*\.\s*ServeFile\s*\(",
        description="ServeFile sends caller-supplied file path.",
        argument_roles=["w", "r", "name"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-dl-http-filesystem",
        function="http.FileServer(http.Dir(userPath))",
        call_regex=r"\bhttp\s*\.\s*FileServer\s*\(\s*http\.\s*Dir\s*\(",
        description="FileServer rooted at dynamic Dir(...) value.",
        argument_roles=["root"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-dl-gin-file",
        function="c.File / c.FileAttachment",
        call_regex=r"\.\s*(?:File|FileAttachment)\s*\(",
        description="Gin File serving with caller-supplied path.",
        argument_roles=["filepath"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
]

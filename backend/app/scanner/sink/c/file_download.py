"""C — File Download sinks (CGI sendfile, raw read/write to socket)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_download"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-dl-sendfile",
        function="sendfile(out_fd, in_fd, offset, count)",
        call_regex=r"\bsendfile(?:64)?\s*\(",
        description="sendfile() streaming caller-supplied file fd to client socket.",
        argument_roles=["out_fd", "in_fd", "offset", "count"],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-dl-mongoose-send-file",
        function="mg_http_serve_file / mg_send_file",
        call_regex=r"\b(?:mg_http_serve_file|mg_send_file)\s*\(",
        description="mongoose helper serving caller-controlled file path.",
        argument_roles=[],
        extensions=_C,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-dl-cgi-include-file",
        function="fread + fwrite(stdout) of caller-controlled path",
        call_regex=r"\bfread\s*\(",
        description="Reading file with dynamic path and writing back to stdout — LFI/download.",
        argument_roles=[],
        extensions=_C,
        severity="low",
        require_dynamic=True,
    ),
]

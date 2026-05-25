"""C — File Upload sinks (CGI / FastCGI / mongoose / civetweb)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-upload-fwrite-userpath",
        function="fwrite to fopen(userPath)",
        call_regex=r"\bfwrite\s*\(",
        description="fwrite to a file opened with caller-supplied path.",
        argument_roles=["ptr", "size", "nmemb", "stream"],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-upload-cgi-upload",
        function="cgi_save_file / mg_upload",
        call_regex=r"\b(?:cgi_save_file|mg_upload|mg_handle_form_request)\s*\(",
        description="CGI helper saving multipart upload — verify destination.",
        argument_roles=[],
        extensions=_C,
        severity="medium",
    ),
]

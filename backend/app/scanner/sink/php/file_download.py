"""PHP — Arbitrary File Download sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_download"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-download-readfile-via-disposition",
        function="readfile + Content-Disposition",
        # 命中 readfile 调用即作为候选；上层会再用 require_dynamic 过滤。
        call_regex=r"\breadfile\s*\(\s*[^)]*\$",
        description="readfile combined with Content-Disposition can leak files.",
        argument_roles=["filename"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-download-fpassthru-dynamic",
        function="fpassthru",
        call_regex=r"\bfpassthru\s*\(",
        description="Streams a file pointer to output; LFD risk if path comes from user.",
        argument_roles=["handle"],
        extensions=_PHP,
        severity="medium",
    ),
    SinkRule(
        id="php-download-header-content-disposition",
        function="header(Content-Disposition)",
        call_regex=r"\bheader\s*\(\s*['\"]Content-Disposition[^)]*\$",
        description="Content-Disposition header constructed from user input.",
        argument_roles=["header"],
        extensions=_PHP,
        severity="low",
        require_dynamic=True,
    ),
]

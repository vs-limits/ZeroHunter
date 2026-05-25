"""PHP — Arbitrary File Inclusion (LFI / RFI) sinks (CWE-98)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_inclusion"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-file-include-dynamic",
        function="include/require",
        # 仅匹配带变量/拼接的 include；纯字面量自然忽略
        call_regex=r"\b(?:include|include_once|require|require_once)\b\s*(?:\(\s*[^)]*\$|[^;]*\$)",
        description="Loads PHP code from a path that contains a variable.",
        argument_roles=["path"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-file-virtual",
        function="virtual",
        call_regex=r"\bvirtual\s*\(",
        description="Apache mod_php virtual() includes another URL.",
        argument_roles=["path"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-file-stream-include",
        function="stream_resolve_include_path",
        call_regex=r"\bstream_resolve_include_path\s*\(",
        description="Resolves a path against include_path; dangerous if user-controlled.",
        argument_roles=["filename"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
]

"""JavaScript / Node.js — Buffer-related memory misuse (CWE-119, CWE-122)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "buffer_overflow"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-buf-buffer-unsafe-alloc",
        function="Buffer.allocUnsafe / new Buffer(N)",
        call_regex=r"\bBuffer\s*\.\s*allocUnsafe(?:Slow)?\s*\(",
        description="allocUnsafe returns uninitialised memory — can leak prior contents.",
        argument_roles=["size"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-buf-new-buffer-deprecated",
        function="new Buffer(size|str|array)",
        call_regex=r"\bnew\s+Buffer\s*\(",
        description="Deprecated Buffer constructor — type confusion + uninit memory.",
        argument_roles=["arg"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-buf-write-offset",
        function="buf.write(string, offset, length)",
        call_regex=r"\.\s*write\s*\(\s*[a-zA-Z_]",
        description="Buffer.write with dynamic offset/length may write past end.",
        argument_roles=["string", "offset", "length"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-buf-copy-noend",
        function="src.copy(dst, ...) without length",
        call_regex=r"\.\s*copy\s*\(",
        description="Buffer.copy with dynamic indexes risks overrun.",
        argument_roles=["target", "targetStart", "sourceStart", "sourceEnd"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
]

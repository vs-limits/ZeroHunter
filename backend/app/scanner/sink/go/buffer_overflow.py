"""Go — Memory/buffer mishandling (typically via cgo / unsafe)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "buffer_overflow"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-buf-unsafe-pointer",
        function="unsafe.Pointer arithmetic",
        call_regex=r"\bunsafe\s*\.\s*Pointer\b",
        description="Pointer arithmetic via unsafe defeats bounds checks.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-buf-unsafe-slice",
        function="unsafe.Slice(ptr, len)",
        call_regex=r"\bunsafe\s*\.\s*Slice\s*\(",
        description="unsafe.Slice with attacker-controlled length = OOB read/write.",
        argument_roles=["ptr", "len"],
        extensions=_GO,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-buf-c-call",
        function="C.<something>(buf, size)",
        call_regex=r"\bC\.\s*\w+\s*\(",
        description="cgo call — verify C side's bounds.",
        argument_roles=[],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-buf-make-dynamic-size",
        function="make([]byte, userInt) without cap",
        call_regex=r"\bmake\s*\(\s*\[\]byte\s*,",
        description="make([]byte, n) where n is unbounded — DoS / OOM.",
        argument_roles=["len"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

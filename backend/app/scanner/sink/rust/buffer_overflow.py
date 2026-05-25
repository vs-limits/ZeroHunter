"""Rust — Memory-safety sinks (unsafe blocks, transmute, slice::from_raw_parts)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "buffer_overflow"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-buf-unsafe-block",
        function="unsafe { ... } block",
        call_regex=r"\bunsafe\s*\{",
        description="unsafe blocks bypass borrow/bounds checks; verify invariants.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-buf-from-raw-parts",
        function="slice::from_raw_parts(ptr, len)",
        call_regex=r"\bslice\s*::\s*from_raw_parts(?:_mut)?\s*\(",
        description="from_raw_parts with attacker-influenced length = OOB.",
        argument_roles=["data", "len"],
        extensions=_RS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-buf-transmute",
        function="mem::transmute",
        call_regex=r"\bmem\s*::\s*transmute\s*(?:::<[^>]+>)?\s*\(",
        description="transmute is wildly unsafe — type-punning UB.",
        argument_roles=[],
        extensions=_RS,
        severity="high",
    ),
    SinkRule(
        id="rs-buf-ptr-copy",
        function="ptr::copy / copy_nonoverlapping",
        call_regex=r"\bptr\s*::\s*copy(?:_nonoverlapping)?\s*\(",
        description="Raw pointer memcpy with dynamic count.",
        argument_roles=["src", "dst", "count"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-buf-vec-set-len",
        function="Vec::set_len(userLen)",
        call_regex=r"\.\s*set_len\s*\(",
        description="set_len trusts caller — exposes uninitialised memory.",
        argument_roles=["new_len"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-buf-mem-uninit",
        function="MaybeUninit::assume_init prematurely",
        call_regex=r"\.\s*assume_init\s*\(",
        description="assume_init on uninitialised MaybeUninit is UB.",
        argument_roles=[],
        extensions=_RS,
        severity="high",
    ),
]

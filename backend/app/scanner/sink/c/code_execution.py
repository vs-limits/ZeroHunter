"""C — Code Execution via dynamic loader (CWE-94)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "code_execution"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-code-dlopen",
        function="dlopen(filename, flags)",
        call_regex=r"\bdlopen\s*\(",
        description="dlopen with caller-controlled .so name loads arbitrary library.",
        argument_roles=["filename", "flags"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-code-dlsym",
        function="dlsym(handle, sym)",
        call_regex=r"\bdlsym\s*\(",
        description="dlsym resolving caller-controlled symbol — pivot for RCE.",
        argument_roles=["handle", "symbol"],
        extensions=_C,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-code-mmap-exec",
        function="mmap(... PROT_EXEC ...)",
        call_regex=r"\bmmap\s*\(",
        description="mmap with PROT_EXEC creates executable region — JIT/RWX surface.",
        argument_roles=["addr", "length", "prot", "flags", "fd", "offset"],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-code-mprotect-exec",
        function="mprotect(addr, len, PROT_EXEC)",
        call_regex=r"\bmprotect\s*\(",
        description="mprotect to PROT_EXEC marks pages executable.",
        argument_roles=["addr", "len", "prot"],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-code-libdl-load-getenv",
        function="LD_PRELOAD / LD_LIBRARY_PATH manipulation",
        call_regex=r"\bsetenv\s*\(\s*\"(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES)\"",
        description="Modifying dynamic-linker env can hijack libraries.",
        argument_roles=[],
        extensions=_C,
        severity="high",
    ),
]

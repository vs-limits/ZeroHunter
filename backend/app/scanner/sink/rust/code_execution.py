"""Rust — Code Execution / Dynamic Loading sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "code_execution"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-code-libloading",
        function="libloading::Library::new(path)",
        call_regex=r"\bLibrary\s*::\s*new\s*\(",
        description="libloading loads arbitrary shared object from caller path.",
        argument_roles=["filename"],
        extensions=_RS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-code-dlopen",
        function="dlopen / dlopen2",
        call_regex=r"\bdlopen\s*\(|\bdlopen2\b",
        description="dlopen with dynamic path loads arbitrary library.",
        argument_roles=["filename"],
        extensions=_RS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-code-wasmer-instantiate",
        function="wasmer::Instance::new(module, imports)",
        call_regex=r"\bInstance\s*::\s*new\s*\(",
        description="wasmer/wasmtime instantiate user-supplied module.",
        argument_roles=["module", "imports"],
        extensions=_RS,
        severity="high",
    ),
    SinkRule(
        id="rs-code-rhai-eval",
        function="rhai Engine.eval(expr)",
        call_regex=r"\bEngine\b[\s\S]{0,40}\.\s*(?:eval|eval_with_scope|run)\s*\(",
        description="rhai script engine executing dynamic script.",
        argument_roles=["script"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
]

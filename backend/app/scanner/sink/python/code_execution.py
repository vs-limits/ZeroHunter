"""Python — Code Execution sinks (CWE-94/95)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "code_execution"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-code-eval",
        function="eval",
        call_regex=r"\beval\s*\(",
        description="Evaluates Python expression text.",
        argument_roles=["expression"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-code-exec",
        function="exec",
        call_regex=r"\bexec\s*\(",
        description="Executes Python statement text.",
        argument_roles=["code"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-code-compile",
        function="compile()",
        call_regex=r"\bcompile\s*\(",
        description="compile() turns a string into a code object; pair with exec/eval.",
        argument_roles=["source", "filename", "mode"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-code-importlib-import-module",
        function="importlib.import_module",
        call_regex=r"\bimportlib\.import_module\s*\(|\b__import__\s*\(",
        description="Dynamic import; module name from user input loads arbitrary modules.",
        argument_roles=["module"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-code-marshal-loads",
        function="marshal.loads",
        call_regex=r"\bmarshal\.loads?\s*\(",
        description="marshal.loads decodes bytecode; can execute arbitrary code via exec.",
        argument_roles=["data"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-code-types-functiontype",
        function="types.FunctionType from bytecode",
        call_regex=r"\btypes\.FunctionType\s*\(",
        description="Constructing a function from caller-supplied code object.",
        argument_roles=["code", "globals"],
        extensions=_PY,
        severity="medium",
    ),
]

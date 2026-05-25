"""Python — File path / read sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_path"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-file-open-dynamic",
        function="open()",
        call_regex=r"\bopen\s*\(",
        description="open() on a caller-controlled path (file read/write).",
        argument_roles=["path", "mode"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-file-pathlib-read",
        function="Path.read_text / read_bytes",
        call_regex=r"\.\s*read_(?:text|bytes)\s*\(",
        description="pathlib.Path.read_* on a tainted Path.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-file-tempfile-named-dynamic",
        function="tempfile with explicit prefix/suffix from input",
        call_regex=r"\btempfile\.NamedTemporaryFile\s*\(",
        description="NamedTemporaryFile with caller-supplied prefix/suffix can be abused.",
        argument_roles=["prefix", "suffix"],
        extensions=_PY,
        severity="low",
        require_dynamic=True,
    ),
]

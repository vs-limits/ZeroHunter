"""Python — Arbitrary File Inclusion / dynamic module load."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_inclusion"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-include-importlib-spec-from-file",
        function="importlib.util.spec_from_file_location",
        call_regex=r"\bspec_from_file_location\s*\(",
        description="Loads a Python module from an arbitrary file path.",
        argument_roles=["name", "location"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-include-runpy",
        function="runpy.run_path",
        call_regex=r"\brunpy\.run_path\s*\(",
        description="runpy.run_path executes a Python file as __main__.",
        argument_roles=["path_name"],
        extensions=_PY,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-include-execfile-py2",
        function="execfile (Py2)",
        call_regex=r"\bexecfile\s*\(",
        description="Py2 execfile() executes a Python source file.",
        argument_roles=["filename"],
        extensions=_PY,
        severity="critical",
    ),
]

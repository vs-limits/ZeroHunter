"""Python — Path Traversal sinks (CWE-22)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "path_traversal"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-path-os-join-tainted",
        function="os.path.join with tainted segment",
        call_regex=r"\bos\.path\.join\s*\(",
        description="os.path.join lets a leading '/' or '..' override earlier segments.",
        argument_roles=["paths"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-path-pathlib-truediv",
        function="Path() / variable",
        call_regex=r"Path\s*\([^)]*\)\s*/\s*\w",
        description="pathlib Path concatenation with a variable.",
        argument_roles=["base", "child"],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-path-zipfile-extract-all",
        function="ZipFile.extractall",
        call_regex=r"\.\s*extractall\s*\(",
        description="extractall is famous for Zip Slip; flag for review.",
        argument_roles=["path", "members"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-path-tarfile-extract-all",
        function="TarFile.extractall",
        call_regex=r"\bTarFile\.extractall\s*\(|\.\s*extractall\s*\(",
        description="TarFile.extractall susceptible to path traversal.",
        argument_roles=["path", "members"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-path-os-remove-dynamic",
        function="os.remove / os.unlink / shutil.rmtree",
        call_regex=r"\b(?:os\.remove|os\.unlink|shutil\.rmtree)\s*\(",
        description="File-deletion APIs called with a variable path.",
        argument_roles=["path"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
]

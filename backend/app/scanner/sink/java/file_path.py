"""Java — generic File-Path operation sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_path"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-path-file-mkdirs",
        function="File.mkdirs / mkdir",
        call_regex=r"\.\s*mkdirs?\s*\(",
        description="Creating directories with caller-supplied path.",
        argument_roles=[],
        extensions=_JAVA,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-file-delete",
        function="File.delete / deleteOnExit",
        call_regex=r"\.\s*delete(?:OnExit)?\s*\(\s*\)",
        description="Deleting File whose path is user-supplied.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-file-renameto",
        function="File.renameTo(File)",
        call_regex=r"\.\s*renameTo\s*\(",
        description="Renaming a file to caller-controlled location.",
        argument_roles=["dest"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-files-createsymboliclink",
        function="Files.createSymbolicLink",
        call_regex=r"\bFiles\s*\.\s*createSymbolicLink\s*\(",
        description="Symbolic link target controlled by attacker can pivot file ops.",
        argument_roles=["link", "target"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
]

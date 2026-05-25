"""C++ — generic File-Path operation sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_path"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-path-fs-permissions",
        function="std::filesystem::permissions(path, perms)",
        call_regex=r"\bstd\s*::\s*filesystem\s*::\s*permissions\s*\(",
        description="Changing fs permissions of caller-controlled path.",
        argument_roles=["p", "perms"],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-path-fs-create-symlink",
        function="std::filesystem::create_symlink",
        call_regex=r"\bstd\s*::\s*filesystem\s*::\s*(?:create_symlink|create_directory_symlink|create_hard_link)\s*\(",
        description="Creating link with attacker-supplied target/path.",
        argument_roles=["target", "link"],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-path-qsavefile-rename",
        function="QSaveFile / QFile rename / setPermissions",
        call_regex=r"\bQ(?:File|SaveFile)\b[\s\S]{0,40}\.\s*(?:rename|setPermissions|moveToTrash)\s*\(",
        description="Qt file path mutation with user input.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
]

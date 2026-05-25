"""C++ — Path Traversal sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "path_traversal"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-path-ifstream-open",
        function="std::ifstream(path) / open(path)",
        call_regex=r"\bstd\s*::\s*(?:i|o|io|f|ifstream|ofstream|fstream)\s*[\w<>]*\s*(?:\(|\.\s*open\s*\()",
        description="C++ file streams opening dynamic path.",
        argument_roles=["filename"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-path-filesystem-read",
        function="std::filesystem::* (read / remove / rename)",
        call_regex=r"\bstd\s*::\s*filesystem\s*::\s*(?:read_symlink|read_link|remove|remove_all|rename|copy|copy_file|directory_iterator|recursive_directory_iterator)\s*\(",
        description="std::filesystem operating on caller-controlled path.",
        argument_roles=["p"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-path-qfile-open",
        function="QFile / QSaveFile open(path)",
        call_regex=r"\bQ(?:File|SaveFile|FileInfo|Dir)\b[\s\S]{0,40}\.\s*(?:open|setFileName|remove|rename|copy)\s*\(",
        description="Qt file APIs with dynamic path.",
        argument_roles=["name"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-path-boost-fs",
        function="boost::filesystem::remove / rename / copy",
        call_regex=r"\bboost\s*::\s*filesystem\s*::\s*(?:remove|remove_all|rename|copy|copy_file|exists)\s*\(",
        description="boost::filesystem operating on dynamic path.",
        argument_roles=["p"],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-path-fopen-cpp",
        function="fopen / open from C++ context",
        call_regex=r"\b(?:std\s*::\s*)?fopen(?:_s)?\s*\(",
        description="fopen called from C++ with dynamic path.",
        argument_roles=["filename", "mode"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
]

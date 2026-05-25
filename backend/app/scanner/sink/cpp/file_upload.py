"""C++ — File Upload sinks (web frameworks)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-upload-drogon-multipart",
        function="MultiPartParser::saveAs(path)",
        call_regex=r"\.\s*saveAs(?:Unique)?\s*\(",
        description="Drogon multipart saving to caller-controlled path.",
        argument_roles=["path"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-upload-crow-multipart",
        function="crow::multipart::message read",
        call_regex=r"\bcrow\s*::\s*multipart\b",
        description="Crow multipart handling — verify filename sanitisation.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-upload-ofstream-userpath",
        function="std::ofstream(userPath)",
        call_regex=r"\bstd\s*::\s*ofstream\s*[\w<>]*\s*\(",
        description="Opening output stream with caller-controlled path while handling upload.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
]

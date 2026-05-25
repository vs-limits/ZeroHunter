"""C++ — File Download sinks (web frameworks)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_download"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-dl-drogon-sendfile",
        function="HttpResponse::newFileResponse(path)",
        call_regex=r"\bnewFileResponse\s*\(",
        description="Drogon FileResponse serving caller-controlled path.",
        argument_roles=["fullPath"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-dl-pistache-static",
        function="Pistache static handler",
        call_regex=r"\bserveFile\s*\(",
        description="Pistache serveFile with caller path.",
        argument_roles=[],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-dl-crow-sendfile",
        function="crow::response::set_static_file_info(path)",
        call_regex=r"\.\s*set_static_file_info\s*\(",
        description="Crow static file serving with dynamic path.",
        argument_roles=["path"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
]

"""C++ — XSS sinks (cppcms, drogon, crow, oat++)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xss"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-xss-drogon-htmldata",
        function="HttpResponse::newHttpResponse() body html",
        call_regex=r"\bsetBody\s*\(",
        description="Drogon setBody / Crow HttpResponse body with concatenated HTML.",
        argument_roles=["body"],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-xss-cppcms-out",
        function="cppcms::response out << html",
        call_regex=r"\bresponse\s*\(\s*\)\s*\.\s*out\s*\(\s*\)",
        description="cppcms response out << untrusted HTML.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
    ),
    SinkRule(
        id="cpp-xss-crow-route-html",
        function="crow::response{html_string}",
        call_regex=r"\bcrow\s*::\s*response\s*\{",
        description="Crow response constructed from concatenated HTML.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
]

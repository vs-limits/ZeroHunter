"""C++ — CRLF / Header injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "crlf_injection"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-crlf-drogon-addheader",
        function="HttpResponse::addHeader / setBody",
        call_regex=r"\.\s*addHeader\s*\(",
        description="Drogon addHeader with caller-controlled value.",
        argument_roles=["field", "value"],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-crlf-qnetwork-rawheader",
        function="QNetworkRequest::setRawHeader",
        call_regex=r"\bsetRawHeader\s*\(",
        description="Qt raw HTTP header setter with dynamic value.",
        argument_roles=["headerName", "value"],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-crlf-poco-response-set",
        function="Poco::Net::HTTPResponse::set",
        call_regex=r"\bHTTPResponse\b[\s\S]{0,40}\.\s*set\s*\(",
        description="Poco HTTP response header from user input.",
        argument_roles=["name", "value"],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
]

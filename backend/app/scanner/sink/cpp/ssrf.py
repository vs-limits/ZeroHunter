"""C++ — SSRF sinks (curlpp, Qt, Poco)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssrf"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-ssrf-qnetworkrequest",
        function="QNetworkRequest(url) / QNetworkAccessManager.get",
        call_regex=r"\bQNetworkRequest\s*\(|\bQNetworkAccessManager\b[\s\S]{0,40}\.\s*(?:get|post|put|deleteResource|sendCustomRequest)\s*\(",
        description="Qt network request with dynamic URL.",
        argument_roles=["url"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-ssrf-curlpp",
        function="curlpp::options::Url",
        call_regex=r"\bcurlpp\s*::\s*options\s*::\s*Url\s*\(",
        description="curlpp Url option with dynamic value.",
        argument_roles=["url"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-ssrf-poco-http",
        function="Poco::Net::HTTPClientSession",
        call_regex=r"\bPoco\s*::\s*Net\s*::\s*HTTP(?:Client)?Session\b",
        description="Poco HTTP session with dynamic host.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-ssrf-asio-connect",
        function="asio::connect / boost::asio::connect",
        call_regex=r"\b(?:boost\s*::\s*)?asio\s*::\s*(?:connect|async_connect)\s*\(",
        description="ASIO socket connect to attacker-controlled endpoint.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-ssrf-cpr-get",
        function="cpr::Get / Post / Put",
        call_regex=r"\bcpr\s*::\s*(?:Get|Post|Put|Patch|Delete|Head|Options)\s*\(",
        description="cpr HTTP client with caller-controlled URL.",
        argument_roles=["url"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
]

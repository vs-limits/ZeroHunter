"""Python — SSRF sinks (CWE-918).

Outbound HTTP/URL fetch primitives where the URL is dynamic.
"""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssrf"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-ssrf-requests",
        function="requests.get/post/put/delete/request",
        call_regex=r"\brequests\.\s*(?:get|post|put|patch|delete|request|head|options)\s*\(",
        description="requests library issuing HTTP call with potentially user-controlled URL.",
        argument_roles=["url", "kwargs"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssrf-urllib-urlopen",
        function="urllib.request.urlopen",
        call_regex=r"\burlopen\s*\(",
        description="urlopen fetches arbitrary URL/scheme (file:// gopher://).",
        argument_roles=["url"],
        extensions=_PY,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssrf-urllib3",
        function="urllib3.PoolManager.request",
        call_regex=r"\.\s*request\s*\(\s*['\"](?:GET|POST|PUT|DELETE)",
        description="urllib3 manual request with method+url.",
        argument_roles=["method", "url"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-ssrf-httpx",
        function="httpx.get/post/Client.request",
        call_regex=r"\bhttpx\.\s*(?:get|post|put|patch|delete|request|head|options)\s*\(",
        description="httpx outbound call with dynamic URL.",
        argument_roles=["url"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssrf-aiohttp",
        function="aiohttp.ClientSession.get/post",
        call_regex=r"\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*[a-zA-Z_]",
        description="aiohttp client method receiving dynamic URL.",
        argument_roles=["url"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssrf-socket-connect",
        function="socket.connect / create_connection",
        call_regex=r"\.\s*(?:connect|create_connection)\s*\(",
        description="Raw socket connect to user-supplied host:port.",
        argument_roles=["address"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssrf-ftplib",
        function="ftplib.FTP",
        call_regex=r"\bFTP\s*\(",
        description="ftplib.FTP connecting to dynamic host.",
        argument_roles=["host"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssrf-pycurl",
        function="pycurl Curl().setopt(URL)",
        call_regex=r"\.\s*setopt\s*\(\s*pycurl\.URL\b",
        description="pycurl URL setopt with dynamic URL.",
        argument_roles=["option", "value"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-ssrf-grpc-channel",
        function="grpc.insecure_channel",
        call_regex=r"\binsecure_channel\s*\(",
        description="gRPC channel target taken from runtime data.",
        argument_roles=["target"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
]

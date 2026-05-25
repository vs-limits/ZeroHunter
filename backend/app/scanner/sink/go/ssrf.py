"""Go — SSRF sinks (CWE-918)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssrf"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-ssrf-http-get",
        function="http.Get / Post / Head / PostForm",
        call_regex=r"\bhttp\s*\.\s*(?:Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)\s*\(",
        description="net/http convenience funcs with dynamic URL.",
        argument_roles=["url"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ssrf-http-client-do",
        function="client.Do(req)",
        call_regex=r"\.\s*Do\s*\(\s*req",
        description="http.Client.Do — verify req.URL came from a trusted source.",
        argument_roles=["req"],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-ssrf-net-dial",
        function="net.Dial / DialTimeout / DialTCP",
        call_regex=r"\bnet\s*\.\s*Dial(?:Timeout|TCP|UDP|IP|Unix)?\s*\(",
        description="Low-level network dial with dynamic address.",
        argument_roles=["network", "address"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ssrf-resty-get",
        function="resty.Client R().Get",
        call_regex=r"\.\s*R\s*\(\s*\)\s*\.\s*(?:Get|Post|Put|Delete|Patch|Head|Options)\s*\(",
        description="resty client request with dynamic URL.",
        argument_roles=["url"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ssrf-grpc-dial",
        function="grpc.Dial / DialContext",
        call_regex=r"\bgrpc\s*\.\s*Dial(?:Context)?\s*\(",
        description="gRPC dial with dynamic target.",
        argument_roles=["target", "opts"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-ssrf-ftp-dial",
        function="ftp.Dial(host:port)",
        call_regex=r"\bftp\s*\.\s*Dial\s*\(",
        description="FTP client connecting to dynamic host.",
        argument_roles=["addr"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

"""C — SSRF sinks (libcurl & raw sockets)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssrf"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-ssrf-curl-easy-setopt-url",
        function="curl_easy_setopt(handle, CURLOPT_URL, url)",
        call_regex=r"\bcurl_easy_setopt\s*\(",
        description="libcurl URL set with caller-controlled string.",
        argument_roles=["handle", "option", "value"],
        extensions=_C,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"CURLOPT_URL"],
    ),
    SinkRule(
        id="c-ssrf-curl-easy-perform",
        function="curl_easy_perform(handle)",
        call_regex=r"\bcurl_easy_perform\s*\(",
        description="Performs HTTP/FTP request previously configured via setopt.",
        argument_roles=["handle"],
        extensions=_C,
        severity="medium",
    ),
    SinkRule(
        id="c-ssrf-getaddrinfo-dynamic",
        function="getaddrinfo(host, port, hints, res)",
        call_regex=r"\bgetaddrinfo\s*\(",
        description="Resolving caller-controlled host enables SSRF / DNS rebinding.",
        argument_roles=["node", "service", "hints", "res"],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-ssrf-socket-connect",
        function="connect(fd, addr, addrlen)",
        call_regex=r"\bconnect\s*\(",
        description="Raw socket connect to attacker-supplied sockaddr.",
        argument_roles=["sockfd", "addr", "addrlen"],
        extensions=_C,
        severity="medium",
        require_dynamic=True,
    ),
]

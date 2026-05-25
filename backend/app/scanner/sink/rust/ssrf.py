"""Rust — SSRF sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssrf"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-ssrf-reqwest-get",
        function="reqwest::get / Client.get/post",
        call_regex=r"\breqwest\s*::\s*(?:get|Client::new|blocking::get)\s*\(|\.\s*(?:get|post|put|delete|patch|head|request)\s*\(",
        description="reqwest HTTP client with dynamic URL.",
        argument_roles=["url"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-ssrf-ureq-get",
        function="ureq::get / agent.get",
        call_regex=r"\bureq\s*::\s*(?:get|post|put|delete|head|patch|request)\s*\(",
        description="ureq HTTP client with dynamic URL.",
        argument_roles=["url"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-ssrf-hyper-uri-from-str",
        function="Uri::from_str(userInput)",
        call_regex=r"\bUri\s*::\s*from_str\s*\(|\bUri\s*::\s*from_static\s*\(",
        description="hyper Uri::from_str of dynamic string.",
        argument_roles=["s"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-ssrf-tokio-tcp-connect",
        function="TcpStream::connect(addr)",
        call_regex=r"\bTcpStream\s*::\s*connect\s*\(",
        description="TCP socket connect to dynamic address.",
        argument_roles=["addr"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-ssrf-isahc-get",
        function="isahc::get / Client.send",
        call_regex=r"\bisahc\s*::\s*(?:get|post|put|delete|send)\s*\(",
        description="isahc HTTP client with dynamic URL.",
        argument_roles=["uri"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
]

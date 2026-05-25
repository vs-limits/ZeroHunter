"""PHP — SSRF sinks (CWE-918)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssrf"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-ssrf-curl-exec",
        function="curl_exec",
        call_regex=r"\bcurl_exec\s*\(",
        description="Performs a cURL request using a previously configured handle.",
        argument_roles=["curl_handle"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-ssrf-curl-setopt-url",
        function="curl_setopt CURLOPT_URL",
        call_regex=r"\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,",
        description="Sets the destination URL of a cURL handle.",
        argument_roles=["handle", "option", "value"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-ssrf-curl-init-dynamic",
        function="curl_init",
        call_regex=r"\bcurl_init\s*\(\s*[^)]*\$",
        description="curl_init with a variable URL.",
        argument_roles=["url"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-ssrf-fopen-url",
        function="fopen URL",
        call_regex=r"\bfopen\s*\(\s*[^)]*\$[^,]*,\s*['\"][rb]+['\"]",
        description="fopen() against a variable URL acts as HTTP fetch when allow_url_fopen is on.",
        argument_roles=["url", "mode"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-ssrf-file-get-contents-url",
        function="file_get_contents URL",
        call_regex=r"\bfile_get_contents\s*\(\s*[^)]*https?://",
        description="file_get_contents against a URL constructed with http(s) prefix.",
        argument_roles=["url"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-ssrf-fsockopen-dynamic",
        function="fsockopen / pfsockopen",
        call_regex=r"\b(?:fsockopen|pfsockopen|stream_socket_client)\s*\(",
        description="Opens a TCP socket to a caller-supplied host/port.",
        argument_roles=["host", "port"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-ssrf-guzzle-request",
        function="GuzzleHttp request",
        # Gate on Guzzle context; bare `->request(` / `->get(` matches almost
        # every PHP service object and produces massive false positives.
        call_regex=r"->\s*(?:request|get|post|put|delete|patch|send|sendAsync)\s*\(",
        description="Guzzle HTTP client request methods; flagged when URL looks dynamic.",
        argument_roles=["method_or_uri"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
        extra_match_regex=[r"Guzzle", r"\$client\b", r"http(?:s)?://", r"new\s+Client\s*\("],
    ),
    SinkRule(
        id="php-ssrf-symfony-httpclient",
        function="Symfony HttpClient::request",
        call_regex=r"HttpClient\s*::\s*create\s*\(|->\s*request\s*\(\s*['\"]GET",
        description="Symfony HttpClient request methods.",
        argument_roles=["url"],
        extensions=_PHP,
        severity="medium",
    ),
]

"""Java — SSRF sinks (CWE-918)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssrf"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-ssrf-url-openconnection",
        function="new URL(s).openConnection()",
        call_regex=r"\bnew\s+URL\s*\(",
        description="java.net.URL constructed from user input then opened.",
        argument_roles=["spec"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssrf-httpclient-execute",
        function="HttpClient.execute(request)",
        call_regex=r"\.\s*execute\s*\(\s*new\s+Http(?:Get|Post|Put|Delete|Head|Patch)\b",
        description="Apache HttpClient executing request with dynamic URL.",
        argument_roles=["request"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssrf-okhttp-newcall",
        function="OkHttpClient.newCall(Request).execute()",
        call_regex=r"\.\s*newCall\s*\(",
        description="OkHttp call with dynamic URL.",
        argument_roles=["request"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssrf-resttemplate",
        function="RestTemplate.getForObject / postForObject / exchange",
        call_regex=r"\bresttemplate[\s\S]{0,40}\.\s*(?:getForObject|getForEntity|postForObject|postForEntity|exchange|execute)\s*\(",
        description="Spring RestTemplate with dynamic URL.",
        argument_roles=["url", "args"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssrf-webclient-get",
        function="WebClient.get().uri(url)",
        call_regex=r"\.\s*uri\s*\(\s*[a-zA-Z_]",
        description="Spring WebClient.uri called with dynamic string.",
        argument_roles=["uri"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssrf-feignclient",
        function="Feign builder.target(URL)",
        call_regex=r"\.\s*target\s*\([^)]+,\s*[a-zA-Z_]",
        description="Feign client target URL built from runtime value.",
        argument_roles=["apiType", "url"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssrf-socket-newsocket",
        function="new Socket(host, port)",
        call_regex=r"\bnew\s+Socket\s*\(",
        description="Raw TCP Socket with dynamic host/port.",
        argument_roles=["host", "port"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-ssrf-jndi-lookup",
        function="InitialContext.lookup(uri)",
        call_regex=r"\.\s*lookup\s*\(",
        description="JNDI lookup with attacker-controlled name (Log4Shell class).",
        argument_roles=["name"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
]

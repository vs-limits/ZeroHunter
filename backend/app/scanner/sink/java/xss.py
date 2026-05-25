"""Java — XSS sinks (CWE-79)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "xss"

_JAVA = [".java", ".kt", ".scala"]
_JSP = [".jsp", ".jspx", ".jspf", ".tag"]

RULES = [
    SinkRule(
        id="java-xss-servlet-getwriter-print",
        function="response.getWriter().print(value)",
        call_regex=r"getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write|format|printf|append)\s*\(",
        description="Writing untrusted data into servlet response body.",
        argument_roles=["data"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-xss-servlet-getoutputstream",
        function="response.getOutputStream().write(bytes)",
        call_regex=r"getOutputStream\s*\(\s*\)\s*\.\s*write\s*\(",
        description="Raw byte output to response — verify content is escaped.",
        argument_roles=["bytes"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-xss-jsp-out-print",
        function="<% out.print(value) %>",
        call_regex=r"\bout\s*\.\s*(?:print|println|write)\s*\(",
        description="JSP scriptlet writing dynamic value with no <c:out>.",
        argument_roles=["value"],
        extensions=_JSP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-xss-jsp-el-no-escape",
        function="<%= request.getParameter(...) %>",
        call_regex=r"<%=\s*request\.\s*getParameter",
        description="JSP expression printing request parameter unescaped.",
        argument_roles=[],
        extensions=_JSP,
        severity="critical",
    ),
    SinkRule(
        id="java-xss-spring-modelandview-html",
        function="ResponseEntity raw HTML body",
        call_regex=r"\bResponseEntity\s*\.\s*ok\s*\(\s*\"<",
        description="Returning HTML literal that includes interpolated user value.",
        argument_roles=["body"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-xss-thymeleaf-utext",
        function="th:utext=\"...\"",
        call_regex=r"\bth:utext\b",
        description="Thymeleaf th:utext outputs unescaped expression.",
        argument_roles=[],
        extensions=[".html", ".xhtml"],
        severity="high",
    ),
    SinkRule(
        id="java-xss-freemarker-noescape",
        function="<#noescape>",
        call_regex=r"<#noescape>",
        description="Freemarker noescape block disables auto escaping.",
        argument_roles=[],
        extensions=[".ftl", ".ftlh"],
        severity="high",
    ),
    SinkRule(
        id="java-xss-velocity-direct",
        function="$!{} unescaped variable",
        call_regex=r"\$!\{[^}]+\}",
        description="Velocity $!{} prints raw value.",
        argument_roles=[],
        extensions=[".vm", ".vsl"],
        severity="medium",
    ),
]

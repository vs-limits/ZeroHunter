"""Java — File / Resource Inclusion sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_inclusion"

_JAVA = [".java", ".kt", ".scala"]
_JSP = [".jsp", ".jspx", ".jspf"]

RULES = [
    SinkRule(
        id="java-incl-jsp-include-dynamic",
        function="<jsp:include page=\"${...}\"/>",
        call_regex=r"<jsp:include\s+page\s*=\s*\"[^\"]*\$",
        description="Dynamic JSP include page tag — local file inclusion risk.",
        argument_roles=[],
        extensions=_JSP,
        severity="critical",
    ),
    SinkRule(
        id="java-incl-requestdispatcher-include",
        function="request.getRequestDispatcher(path).include/forward",
        call_regex=r"\bgetRequestDispatcher\s*\(",
        description="Servlet RequestDispatcher with dynamic path may include arbitrary view.",
        argument_roles=["path"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-incl-pagecontext-include",
        function="pageContext.include(relativeUrl)",
        call_regex=r"\bpageContext\s*\.\s*include\s*\(",
        description="JSP pageContext.include with dynamic URL.",
        argument_roles=["relativeUrl"],
        extensions=_JSP + _JAVA,
        severity="high",
        require_dynamic=True,
    ),
]

"""Java — CRLF / Response Splitting sinks (CWE-93, CWE-113)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "crlf_injection"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-crlf-response-setheader",
        function="HttpServletResponse.setHeader / addHeader",
        call_regex=r"\.\s*(?:setHeader|addHeader|setIntHeader|addIntHeader|setDateHeader|addDateHeader)\s*\(",
        description="Setting response header with user-controlled value.",
        argument_roles=["name", "value"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-crlf-response-sendredirect",
        function="HttpServletResponse.sendRedirect",
        call_regex=r"\.\s*sendRedirect\s*\(",
        description="sendRedirect with user-controlled URL can split response.",
        argument_roles=["location"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-crlf-response-addcookie",
        function="HttpServletResponse.addCookie(new Cookie(name, value))",
        call_regex=r"\.\s*addCookie\s*\(",
        description="Cookie name/value built from user input — CRLF injection in Set-Cookie.",
        argument_roles=["cookie"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-crlf-spring-redirect-view",
        function="new RedirectView(userInput)",
        call_regex=r"\bnew\s+RedirectView\s*\(",
        description="Spring RedirectView with dynamic URL.",
        argument_roles=["url"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-crlf-mailmessage-setheader",
        function="MimeMessage.setHeader / addHeader",
        call_regex=r"\bMimeMessage\b[\s\S]{0,80}\.\s*(?:setHeader|addHeader|setSubject)\s*\(",
        description="JavaMail header / subject from user input — SMTP header injection.",
        argument_roles=["name", "value"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
]

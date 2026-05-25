"""Python — Information Disclosure sinks (CWE-200, CWE-209, CWE-532)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "info_disclosure"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-info-traceback-format-exc",
        function="traceback.format_exc / print_exc",
        call_regex=r"\btraceback\.\s*(?:format_exc|print_exc|format_exception)\s*\(",
        description="Returning a traceback to the client leaks internal paths/structure.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-info-flask-debug",
        function="Flask app.run(debug=True)",
        call_regex=r"\.\s*run\s*\([^)]*debug\s*=\s*True",
        description="Debug mode exposes the Werkzeug interactive debugger.",
        argument_roles=[],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-info-django-debug",
        function="DEBUG = True",
        call_regex=r"\bDEBUG\s*=\s*True",
        description="Django DEBUG=True returns detailed error pages.",
        argument_roles=[],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-info-print-secret",
        function="print of credential",
        call_regex=r"\bprint\s*\([^)]*(?:password|secret|api_?key|token)",
        description="print() of secret-named variable likely lands in logs.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-info-logging-secret",
        function="logger.* containing secret variable",
        call_regex=r"\blog(?:ger|ging)\.\s*(?:debug|info|warning|error|exception|critical)\s*\([^)]*(?:password|secret|api_?key|token)",
        description="Logging a secret-named variable.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-info-pprint-request",
        function="pprint of request/response",
        call_regex=r"\bpprint\s*\(\s*(?:request|response|environ)",
        description="pprint of full request/response leaks headers (cookies).",
        argument_roles=[],
        extensions=_PY,
        severity="low",
    ),
    SinkRule(
        id="py-info-os-environ-dump",
        function="os.environ.items() into response",
        call_regex=r"os\.environ\.\s*(?:items|copy|dict)\s*\(",
        description="Exporting environment to response leaks secrets.",
        argument_roles=[],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-info-version-header",
        function="Server / X-Powered-By header set",
        call_regex=r"\.\s*headers\s*\[\s*['\"](?:Server|X-Powered-By|X-AspNet-Version)['\"]",
        description="Setting Server / X-Powered-By with framework version.",
        argument_roles=[],
        extensions=_PY,
        severity="low",
    ),
]

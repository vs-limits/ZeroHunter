"""PHP — Unauthorized Access / missing authz patterns."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "unauthorized_access"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-unauth-direct-superglobal-action",
        function="$_GET['action'] / $_REQUEST['action']",
        call_regex=r"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"](?:action|cmd|do|task|method)['\"]\s*\]",
        description="Routing on a superglobal action without an authz gate is a typical IDOR/unauth pattern.",
        argument_roles=["field"],
        extensions=_PHP,
        severity="medium",
    ),
    SinkRule(
        id="php-unauth-direct-id-load",
        function="findById / loadById with $_GET['id']",
        call_regex=r"\b(?:loadBy|findBy|getBy|fetchBy)?(?:Id|ID)\s*\(\s*\$_(?:GET|POST|REQUEST)",
        description="Loading by a raw user-supplied ID without authorization check.",
        argument_roles=["id"],
        extensions=_PHP,
        severity="medium",
    ),
]

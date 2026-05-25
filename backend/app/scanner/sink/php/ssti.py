"""PHP — Server-Side Template Injection sinks (CWE-1336)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "ssti"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-ssti-twig-createTemplate",
        function="Twig\\Environment::createTemplate",
        call_regex=r"->\s*createTemplate\s*\(",
        description="Twig::createTemplate compiles a template from a string; tainted string -> SSTI -> RCE.",
        argument_roles=["template_source"],
        extensions=_PHP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-ssti-twig-render-string",
        function="Twig render with raw source",
        call_regex=r"->\s*render\s*\(\s*['\"]?\$",
        description="Twig render() of a variable template name/source.",
        argument_roles=["template", "context"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-ssti-smarty-eval",
        function="Smarty::eval",
        call_regex=r"->\s*eval\s*\(",
        description="Smarty's eval() executes a template string.",
        argument_roles=["source"],
        extensions=_PHP,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-ssti-blade-compile-string",
        function="Blade::compileString",
        call_regex=r"Blade\s*::\s*compileString\s*\(|->\s*compileString\s*\(",
        description="Compiles a Blade template from a string.",
        argument_roles=["source"],
        extensions=_PHP,
        severity="critical",
        require_dynamic=True,
    ),
]

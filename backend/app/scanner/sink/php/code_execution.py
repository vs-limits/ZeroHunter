"""PHP — Code Execution sinks (CWE-94/95)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "code_execution"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-code-eval",
        function="eval",
        call_regex=r"\beval\s*\(",
        description="Evaluates a string as PHP code.",
        argument_roles=["code"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-code-create-function",
        function="create_function",
        call_regex=r"\bcreate_function\s*\(",
        description="Legacy create_function builds a callable from a code string.",
        argument_roles=["args", "code"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-code-assert",
        function="assert",
        call_regex=r"\bassert\s*\(",
        description="assert() can evaluate a string as PHP code in PHP < 8.",
        argument_roles=["assertion"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-code-call-user-func",
        function="call_user_func",
        call_regex=r"\bcall_user_func(?:_array)?\s*\(",
        description="Invokes a callable; dangerous when callable name is user-controlled.",
        argument_roles=["callable", "args"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-code-callback",
        function="dynamic-callback functions",
        # Only flag when the callback (1st arg) is a string/variable, not an
        # inline closure. `array_map(function() {...}, $arr)` is benign and
        # otherwise dominates the report for any real PHP project.
        call_regex=r"\b(?:array_map|array_filter|array_walk(?:_recursive)?|usort|uasort|uksort|preg_replace_callback|preg_replace_callback_array)\s*\(\s*(?:\$|['\"])",
        description="Higher-order PHP functions taking callables; dangerous when callable string is user-controlled.",
        argument_roles=["callable_or_array"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-code-preg-replace-e",
        function="preg_replace /e flag",
        call_regex=r"\bpreg_replace\s*\(\s*['\"][^'\"]*[/#].*e",
        description="preg_replace with /e modifier evaluates replacement as PHP code (PHP < 7).",
        argument_roles=["pattern", "replacement", "subject"],
        extensions=_PHP,
        severity="critical",
    ),
]

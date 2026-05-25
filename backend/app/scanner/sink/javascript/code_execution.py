"""JavaScript — Code Execution / Dynamic JS evaluation sinks (CWE-94, CWE-95)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "code_execution"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-code-eval",
        function="eval(code)",
        call_regex=r"\beval\s*\(",
        description="eval() executes its string argument as JS.",
        argument_roles=["source"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-code-function-ctor",
        function="new Function(code)",
        call_regex=r"\bnew\s+Function\s*\(",
        description="Function constructor compiles a body string into executable code.",
        argument_roles=["args", "body"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-code-settimeout-string",
        function="setTimeout / setInterval with string",
        call_regex=r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]",
        description="Passing a string to setTimeout/setInterval triggers an internal eval.",
        argument_roles=["handler"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-code-vm-runinnewcontext",
        function="vm.runInNewContext",
        call_regex=r"\bvm\s*\.\s*runIn(?:NewContext|ThisContext|Context)\s*\(",
        description="Node vm sandbox executes JS string (sandbox often escapable).",
        argument_roles=["code", "sandbox"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-code-vm-script",
        function="new vm.Script(code).runIn*",
        call_regex=r"\bnew\s+vm\s*\.\s*Script\s*\(",
        description="Compiling vm.Script from user input.",
        argument_roles=["code"],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-code-require-dynamic",
        function="require(userInput)",
        call_regex=r"\brequire\s*\(\s*(?:[a-zA-Z_][\w.]*|`[^`]*\$\{)",
        description="Dynamic require() argument allows arbitrary module load.",
        argument_roles=["id"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-code-import-dynamic",
        function="import(userInput)",
        call_regex=r"\bimport\s*\(\s*(?:[a-zA-Z_][\w.]*|`[^`]*\$\{)",
        description="Dynamic import() with user input loads arbitrary module/URL.",
        argument_roles=["specifier"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-code-script-src-dynamic",
        function="script.src = userValue",
        call_regex=r"\.\s*src\s*=\s*[^;]*\+|\.\s*src\s*=\s*`[^`]*\$\{",
        description="Dynamic script element src loads external code.",
        argument_roles=["src"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-code-handlebars-compile-dynamic",
        function="Handlebars.compile(userInput)",
        call_regex=r"\bHandlebars\s*\.\s*compile\s*\(",
        description="Handlebars.compile with user-controlled template (also SSTI-class).",
        argument_roles=["input"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
]

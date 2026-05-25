"""JavaScript / Node.js — File / Module Inclusion sinks (CWE-98)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_inclusion"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-incl-require-dynamic",
        function="require(userValue)",
        call_regex=r"\brequire\s*\(\s*(?:[a-zA-Z_][\w]*|`[^`]*\$\{)",
        description="require() given a non-literal — arbitrary module load.",
        argument_roles=["id"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-incl-import-dynamic",
        function="import(userValue)",
        call_regex=r"\bimport\s*\(\s*(?:[a-zA-Z_][\w]*|`[^`]*\$\{)",
        description="Dynamic ESM import() with user value.",
        argument_roles=["specifier"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-incl-loadnodelibrary",
        function="process.dlopen / node-gyp loadNodeAddon",
        call_regex=r"\bprocess\s*\.\s*dlopen\s*\(",
        description="process.dlopen loads native addon by path.",
        argument_roles=["module", "filename", "flags"],
        extensions=_JS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-incl-fs-readfile-then-eval",
        function="fs.readFile(...) → eval",
        call_regex=r"\bfs\s*\.\s*readFile(?:Sync)?\s*\(",
        description="Reading file and then eval'ing — flag for review.",
        argument_roles=["path"],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-incl-template-include",
        function="ejs / pug / hbs include with dynamic name",
        call_regex=r"\binclude\s*\(\s*[a-zA-Z_]",
        description="Template engine include() with dynamic template name.",
        argument_roles=["template"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
]

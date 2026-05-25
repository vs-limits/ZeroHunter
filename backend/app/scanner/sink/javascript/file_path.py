"""JavaScript / Node.js — generic File-Path operation sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_path"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-path-fs-existssync",
        function="fs.existsSync(path)",
        call_regex=r"\bfs\s*\.\s*(?:existsSync|access|accessSync|stat|statSync|lstat|lstatSync)\s*\(",
        description="fs metadata calls with dynamic path; reveal-existence side-channel.",
        argument_roles=["path"],
        extensions=_JS,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-fs-mkdir",
        function="fs.mkdir / mkdirSync",
        call_regex=r"\bfs\s*\.\s*mkdir(?:Sync)?\s*\(",
        description="Creating directory with dynamic path.",
        argument_roles=["path", "options"],
        extensions=_JS,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-fs-chmod",
        function="fs.chmod / chown",
        call_regex=r"\bfs\s*\.\s*(?:chmod|chmodSync|chown|chownSync|fchmod|fchown)\s*\(",
        description="Changing permissions/ownership of an arbitrary file.",
        argument_roles=["path", "mode"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-fs-symlink",
        function="fs.symlink / link",
        call_regex=r"\bfs\s*\.\s*(?:symlink|link|symlinkSync|linkSync)\s*\(",
        description="Creating link with user-supplied target/path enables TOCTOU/escape.",
        argument_roles=["target", "path"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-glob-dynamic",
        function="glob(pattern, ...) with dynamic pattern",
        call_regex=r"\bglob(?:Sync)?\s*\(",
        description="glob() pattern fed from user input — can read arbitrary tree.",
        argument_roles=["pattern", "options"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
]

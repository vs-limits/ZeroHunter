"""JavaScript / Node.js — Path Traversal sinks (CWE-22)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "path_traversal"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-path-fs-readfile",
        function="fs.readFile / readFileSync",
        call_regex=r"\bfs\s*\.\s*readFile(?:Sync)?\s*\(",
        description="fs.readFile with caller-controlled path.",
        argument_roles=["path", "options"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-fs-writefile",
        function="fs.writeFile / writeFileSync / appendFile",
        call_regex=r"\bfs\s*\.\s*(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(",
        description="fs write APIs with dynamic path.",
        argument_roles=["path", "data"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-fs-unlink",
        function="fs.unlink / rmdir / rm",
        call_regex=r"\bfs\s*\.\s*(?:unlink|unlinkSync|rmdir|rm|rmSync)\s*\(",
        description="Deleting an entry by caller-supplied path.",
        argument_roles=["path"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-fs-rename",
        function="fs.rename / copyFile",
        call_regex=r"\bfs\s*\.\s*(?:rename|renameSync|copyFile|copyFileSync)\s*\(",
        description="Renaming/copying files with user-supplied src/dst.",
        argument_roles=["src", "dst"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-fs-createreadstream",
        function="fs.createReadStream",
        call_regex=r"\bfs\s*\.\s*createReadStream\s*\(",
        description="createReadStream with user path can read arbitrary file.",
        argument_roles=["path"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-express-sendfile",
        function="res.sendFile / res.download",
        call_regex=r"\bres\s*\.\s*(?:sendFile|download)\s*\(",
        description="Express sendFile/download with caller-supplied path.",
        argument_roles=["path"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-path-join-traversal",
        function="path.join(base, userInput)",
        call_regex=r"\bpath\s*\.\s*(?:join|resolve)\s*\(",
        description="path.join/resolve does NOT block `..` segments.",
        argument_roles=["...paths"],
        extensions=_JS,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-path-koa-send",
        function="koa-send / serve-static",
        call_regex=r"\bsend\s*\(\s*ctx\s*,\s*[^)]+\)",
        description="koa-send file path argument from user.",
        argument_roles=["ctx", "path"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
]

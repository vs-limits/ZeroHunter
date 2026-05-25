"""JavaScript / Node.js — Arbitrary File Download sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_download"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-dl-express-sendfile",
        function="res.sendFile / res.download",
        call_regex=r"\bres\s*\.\s*(?:sendFile|download)\s*\(",
        description="Express response file delivery with dynamic path.",
        argument_roles=["path", "options"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-dl-koa-send",
        function="koa-send(ctx, path)",
        call_regex=r"\bsend\s*\(\s*ctx\s*,",
        description="koa-send leaks files when no root is enforced.",
        argument_roles=["ctx", "path"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-dl-serve-static-userdir",
        function="serve-static(root, ...)",
        call_regex=r"\bserveStatic\s*\(|\bserve[-_]static\s*\(",
        description="serve-static mounting with user-controlled root.",
        argument_roles=["root"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-dl-fs-create-read-stream-pipe",
        function="fs.createReadStream(path).pipe(res)",
        call_regex=r"\bfs\s*\.\s*createReadStream\s*\([^)]+\)\s*\.\s*pipe\s*\(",
        description="Streaming caller-supplied file to response.",
        argument_roles=["path"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
]

"""JavaScript / Node.js — Arbitrary File Upload sinks (CWE-434)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-upload-multer-diskstorage",
        function="multer.diskStorage filename(req, file, cb)",
        call_regex=r"\bmulter\s*\.\s*diskStorage\s*\(",
        description="multer diskStorage with user-controlled filename callback.",
        argument_roles=["options"],
        extensions=_JS,
        severity="high",
    ),
    SinkRule(
        id="js-upload-formidable-keepextensions",
        function="formidable keepExtensions:true",
        call_regex=r"keepExtensions\s*:\s*true",
        description="formidable keepExtensions preserves attacker-supplied extension.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-upload-busboy-file",
        function="busboy 'file' event piped to fs",
        call_regex=r"\bbusboy\b[\s\S]{0,80}\.\s*on\s*\(\s*['\"]file['\"]",
        description="busboy file event handler — verify filename validation.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-upload-express-fileupload",
        function="express-fileupload mv",
        call_regex=r"\.\s*mv\s*\(",
        description="express-fileupload .mv() persists uploaded file at given path.",
        argument_roles=["path", "callback"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-upload-fs-rename-into-public",
        function="fs.rename(uploadTmp, '/public/...')",
        call_regex=r"\bfs\s*\.\s*rename(?:Sync)?\s*\(",
        description="Renaming temp upload into a public path; check destination.",
        argument_roles=["src", "dst"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
]

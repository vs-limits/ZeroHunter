"""PHP — Path Traversal sinks (CWE-22)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "path_traversal"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-path-realpath-dynamic",
        function="realpath",
        call_regex=r"\brealpath\s*\(\s*[^)]*\$",
        description="realpath() resolves a user-controlled path; result may bypass containment checks.",
        argument_roles=["path"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-path-basename-dynamic",
        function="basename",
        call_regex=r"\bbasename\s*\(\s*[^)]*\$",
        description="basename() does not block ../; flagged when paired with file ops.",
        argument_roles=["path"],
        extensions=_PHP,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-path-dirname-concat",
        function="path concatenation with $",
        call_regex=r"\bdirname\s*\([^)]*\)\s*\.\s*['\"][^'\"]*\$",
        description="Path concatenation involving dirname() and a variable.",
        argument_roles=["path"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-path-unlink-dynamic",
        function="unlink",
        call_regex=r"\bunlink\s*\(\s*[^)]*\$",
        description="Deletes a file at a variable path; arbitrary file deletion.",
        argument_roles=["path"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-path-rename-dynamic",
        function="rename",
        call_regex=r"\brename\s*\(\s*[^)]*\$",
        description="Renames a file using a variable path; arbitrary move.",
        argument_roles=["from", "to"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-path-copy-dynamic",
        function="copy",
        call_regex=r"\bcopy\s*\(\s*[^)]*\$",
        description="Copies a file using a variable source/destination.",
        argument_roles=["from", "to"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-path-file-put-contents",
        function="file_put_contents",
        call_regex=r"\bfile_put_contents\s*\(",
        description="file_put_contents writes to caller-supplied path; web-shell risk if path & content are user-controlled.",
        argument_roles=["filename", "data", "flags"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-path-mkdir-dynamic",
        function="mkdir",
        call_regex=r"\bmkdir\s*\(\s*[^)]*\$",
        description="Creates a directory at a variable path.",
        argument_roles=["path", "mode"],
        extensions=_PHP,
        severity="low",
        require_dynamic=True,
    ),
]

"""PHP — File path manipulation / read sinks.

Generic file reads. Path traversal lives in path_traversal.py;
file download lives in file_download.py.
"""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_path"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-file-get-contents-dynamic",
        function="file_get_contents",
        call_regex=r"\bfile_get_contents\s*\(\s*[^)]*\$",
        description="Reads local or remote content from a path/URL containing a variable.",
        argument_roles=["path_or_url"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-file-fopen-dynamic",
        function="fopen",
        call_regex=r"\bfopen\s*\(\s*[^)]*\$",
        description="Opens a file/stream based on a variable path.",
        argument_roles=["path", "mode"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-file-fread",
        function="fread",
        call_regex=r"\bfread\s*\(",
        description="Reads from a file handle; flagged when paired with dynamic fopen.",
        argument_roles=["handle", "length"],
        extensions=_PHP,
        severity="low",
    ),
    SinkRule(
        id="php-file-readfile-dynamic",
        function="readfile",
        call_regex=r"\breadfile\s*\(\s*[^)]*\$",
        description="Outputs a file directly to the response; LFD risk.",
        argument_roles=["filename"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-file-file-dynamic",
        function="file()",
        # `\b` won't reject `_file(` or `$file(`. Match a leading non-ident /
        # non-`$` char (or BOL) before `file(` so ripgrep (Rust regex, no
        # lookbehind) keeps it precise.
        call_regex=r"(?:^|[^\w$])file\s*\(\s*[^)]*\$",
        description="file() reads a file as array; LFI/LFD risk.",
        argument_roles=["filename"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-file-glob-dynamic",
        function="glob",
        call_regex=r"\bglob\s*\(\s*[^)]*\$",
        description="glob() expands a variable pattern; can leak file system layout.",
        argument_roles=["pattern"],
        extensions=_PHP,
        severity="low",
        require_dynamic=True,
    ),
]

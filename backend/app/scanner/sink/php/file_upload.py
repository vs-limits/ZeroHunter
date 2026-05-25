"""PHP — Arbitrary File Upload sinks (CWE-434)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-upload-move-uploaded-file",
        function="move_uploaded_file",
        call_regex=r"\bmove_uploaded_file\s*\(",
        description="Moves a POST upload to a destination path; missing extension validation is a classic upload bug.",
        argument_roles=["from", "to"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-upload-copy-tmp",
        function="copy with $_FILES tmp_name",
        call_regex=r"\bcopy\s*\([^,]*\$_FILES",
        description="Direct copy() of an uploaded tmp file.",
        argument_roles=["from", "to"],
        extensions=_PHP,
        severity="high",
    ),
    SinkRule(
        id="php-upload-files-superglobal",
        function="$_FILES superglobal usage",
        call_regex=r"\$_FILES\s*\[",
        description="Direct $_FILES read; pair with extension/MIME checks.",
        argument_roles=["field"],
        extensions=_PHP,
        severity="low",
    ),
    SinkRule(
        id="php-upload-rename-tmp",
        function="rename with uploaded file",
        call_regex=r"\brename\s*\(\s*\$_FILES",
        description="Renames the tmp upload directly into webroot.",
        argument_roles=["from", "to"],
        extensions=_PHP,
        severity="high",
    ),
]

"""Rust — File Upload sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-upload-actix-multipart",
        function="actix_multipart::Multipart while_some",
        call_regex=r"\bMultipart\b[\s\S]{0,40}\.\s*next\s*\(\s*\)",
        description="actix multipart upload — verify filename validation before writing.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-upload-warp-form",
        function="warp::multipart::form",
        call_regex=r"\bwarp\s*::\s*multipart\s*::\s*form\s*\(",
        description="warp multipart form handler — verify filename sanitisation.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-upload-axum-multipart",
        function="axum::extract::Multipart",
        call_regex=r"\baxum\s*::\s*extract\s*::\s*Multipart\b",
        description="axum Multipart extractor — verify filename + extension allowlist.",
        argument_roles=[],
        extensions=_RS,
        severity="medium",
    ),
    SinkRule(
        id="rs-upload-tokio-file-create-userpath",
        function="tokio::fs::File::create(userPath)",
        call_regex=r"\bFile\s*::\s*create\s*\(",
        description="Creating file with caller-controlled destination — write outside upload dir.",
        argument_roles=["path"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
]

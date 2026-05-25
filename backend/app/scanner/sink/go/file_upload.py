"""Go — File Upload sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-upload-formfile",
        function="r.FormFile / r.MultipartReader",
        call_regex=r"\.\s*(?:FormFile|MultipartReader)\s*\(",
        description="Reading multipart upload — verify filename and content-type.",
        argument_roles=["key"],
        extensions=_GO,
        severity="medium",
    ),
    SinkRule(
        id="go-upload-saveuploadedfile",
        function="c.SaveUploadedFile(file, dst)",
        call_regex=r"\.\s*SaveUploadedFile\s*\(",
        description="Gin SaveUploadedFile saving with user-controlled destination.",
        argument_roles=["file", "dst"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-upload-io-copy-to-os",
        function="io.Copy(dstFile, uploadStream)",
        call_regex=r"\bio\s*\.\s*Copy\s*\(",
        description="Streaming upload to disk; verify destination path.",
        argument_roles=["dst", "src"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
]

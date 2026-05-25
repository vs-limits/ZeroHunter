"""Python — Arbitrary File Upload sinks (CWE-434)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-upload-flask-save",
        function="werkzeug FileStorage.save",
        call_regex=r"\.\s*save\s*\(",
        description="FileStorage.save() persists upload — path/filename validation needed.",
        argument_roles=["dst"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-upload-flask-secure-filename-absent",
        function="upload without secure_filename",
        call_regex=r"request\.files\s*\[",
        description="Direct request.files[...] access; verify secure_filename + extension allowlist.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-upload-django-modelfile-save",
        function="FileField.save / Storage.save",
        call_regex=r"\.\s*save\s*\(\s*[a-zA-Z_]",
        description="Django Storage.save with caller-supplied filename.",
        argument_roles=["name", "content"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-upload-fastapi-uploadfile",
        function="UploadFile.read / write",
        call_regex=r"\bUploadFile\b[^\n]{0,80}\.(?:read|write|seek)\s*\(",
        description="FastAPI UploadFile persisted with user-controlled filename.",
        argument_roles=[],
        extensions=_PY,
        severity="medium",
    ),
    SinkRule(
        id="py-upload-shutil-copyfileobj",
        function="shutil.copyfileobj(upload, fp)",
        call_regex=r"\bshutil\.\s*copyfileobj\s*\(",
        description="Stream user upload to disk; check destination path.",
        argument_roles=["fsrc", "fdst"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-upload-open-write-binary",
        function="open(path, 'wb') for upload",
        call_regex=r"\bopen\s*\(\s*[^,)]+,\s*['\"][wa]b?['\"]",
        description="Opening a file for binary write with dynamic path — possible upload sink.",
        argument_roles=["file", "mode"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-upload-os-rename",
        function="os.rename / os.replace",
        call_regex=r"\bos\.\s*(?:rename|replace)\s*\(",
        description="Renaming uploaded temp file into web-served directory.",
        argument_roles=["src", "dst"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
]

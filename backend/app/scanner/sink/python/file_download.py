"""Python — Arbitrary File Download sinks (CWE-22/CWE-552 cousin)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_download"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-dl-flask-send-file",
        function="flask.send_file",
        call_regex=r"\bsend_file\s*\(",
        description="send_file with dynamic path can read arbitrary file off disk.",
        argument_roles=["filename_or_fp"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-dl-flask-send-from-directory",
        function="flask.send_from_directory",
        call_regex=r"\bsend_from_directory\s*\(",
        description="send_from_directory with dynamic filename joined to base dir.",
        argument_roles=["directory", "path"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-dl-django-fileresponse",
        function="django.http.FileResponse",
        call_regex=r"\bFileResponse\s*\(",
        description="FileResponse(open(path, 'rb')) — path needs validation.",
        argument_roles=["streaming_content"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-dl-django-static-serve",
        function="django.views.static.serve",
        call_regex=r"\bviews\.static\.\s*serve\s*\(",
        description="static.serve view in production exposes arbitrary directory.",
        argument_roles=["request", "path", "document_root"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-dl-fastapi-fileresponse",
        function="fastapi.responses.FileResponse",
        call_regex=r"\bFileResponse\s*\(",
        description="FastAPI FileResponse path is server-controlled — verify user can't inject.",
        argument_roles=["path"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-dl-starlette-fileresponse",
        function="starlette.responses.FileResponse",
        call_regex=r"\bstarlette\.responses\.\s*FileResponse\s*\(",
        description="Starlette FileResponse with dynamic path.",
        argument_roles=["path"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-dl-open-read-dynamic",
        function="open(path, 'rb') then return",
        call_regex=r"\bopen\s*\(\s*[a-zA-Z_][\w\.]*\s*,\s*['\"]rb?['\"]",
        description="Reading a file with caller-supplied path before returning it.",
        argument_roles=["file", "mode"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
]

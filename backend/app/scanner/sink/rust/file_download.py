"""Rust — File Download sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_download"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-dl-actix-namedfile-open",
        function="NamedFile::open(path)",
        call_regex=r"\bNamedFile\s*::\s*open(?:_async)?\s*\(",
        description="actix-files NamedFile served with caller-controlled path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-dl-warp-file",
        function="warp::fs::file / dir",
        call_regex=r"\bwarp\s*::\s*fs\s*::\s*(?:file|dir)\s*\(",
        description="warp fs::file/dir mounting caller-supplied path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-dl-rocket-namedfile",
        function="rocket::fs::NamedFile::open",
        call_regex=r"\brocket\s*::\s*fs\s*::\s*NamedFile\s*::\s*open\s*\(",
        description="Rocket NamedFile open with dynamic path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-dl-axum-servedir",
        function="tower_http::services::ServeDir / ServeFile",
        call_regex=r"\bServe(?:Dir|File)\s*::\s*new\s*\(",
        description="tower_http file serving with caller-supplied root/path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
]

"""Rust — Path Traversal sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "path_traversal"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-path-fs-read",
        function="std::fs::read / read_to_string / File::open",
        call_regex=r"\bfs\s*::\s*(?:read|read_to_string|read_dir|metadata|symlink_metadata)\s*\(|File\s*::\s*open\s*\(",
        description="std::fs read APIs with dynamic path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-path-fs-write",
        function="std::fs::write / OpenOptions write",
        call_regex=r"\bfs\s*::\s*write\s*\(|OpenOptions\s*::\s*new\s*\(\s*\)\s*\.\s*write",
        description="std::fs write APIs with dynamic path.",
        argument_roles=["path", "contents"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-path-fs-remove",
        function="std::fs::remove_file / remove_dir / remove_dir_all",
        call_regex=r"\bfs\s*::\s*(?:remove_file|remove_dir|remove_dir_all|rename)\s*\(",
        description="std::fs remove/rename with dynamic path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-path-pathbuf-push-user",
        function="path.join / push(userInput)",
        call_regex=r"\.\s*(?:join|push)\s*\(",
        description="PathBuf.join / push with user input — `..` not blocked.",
        argument_roles=["path"],
        extensions=_RS,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-path-actix-namedfile-open",
        function="NamedFile::open(path)",
        call_regex=r"\bNamedFile\s*::\s*open(?:_async)?\s*\(",
        description="actix-files NamedFile::open with caller-controlled path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-path-tokio-fs-read",
        function="tokio::fs::read / open",
        call_regex=r"\btokio\s*::\s*fs\s*::\s*(?:read|read_to_string|File::open)\s*\(",
        description="Async fs reading dynamic path.",
        argument_roles=["path"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
]

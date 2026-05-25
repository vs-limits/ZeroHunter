"""Go — Path Traversal sinks (CWE-22)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "path_traversal"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-path-os-open",
        function="os.Open / OpenFile / Create",
        call_regex=r"\bos\s*\.\s*(?:Open|OpenFile|Create|CreateTemp)\s*\(",
        description="os file open with dynamic path.",
        argument_roles=["name"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-os-readfile",
        function="os.ReadFile / ioutil.ReadFile",
        call_regex=r"\b(?:os|ioutil)\s*\.\s*ReadFile\s*\(",
        description="ReadFile with caller-supplied path can read arbitrary file.",
        argument_roles=["filename"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-os-writefile",
        function="os.WriteFile / ioutil.WriteFile",
        call_regex=r"\b(?:os|ioutil)\s*\.\s*WriteFile\s*\(",
        description="WriteFile with user path — overwrite risk.",
        argument_roles=["filename", "data", "perm"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-os-remove",
        function="os.Remove / RemoveAll",
        call_regex=r"\bos\s*\.\s*(?:Remove|RemoveAll)\s*\(",
        description="Removing path provided by user — arbitrary delete.",
        argument_roles=["name"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-filepath-join-traversal",
        function="filepath.Join(base, userInput)",
        call_regex=r"\bfilepath\s*\.\s*(?:Join|Clean)\s*\(",
        description="filepath.Join does not block `..` segments.",
        argument_roles=["elem"],
        extensions=_GO,
        severity="low",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-http-servefile",
        function="http.ServeFile(w, r, path)",
        call_regex=r"\bhttp\s*\.\s*ServeFile\s*\(",
        description="http.ServeFile with dynamic path — serves any file off disk.",
        argument_roles=["w", "r", "name"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-gin-file",
        function="c.File / c.FileAttachment",
        call_regex=r"\.\s*(?:File|FileAttachment)\s*\(",
        description="Gin File* helpers serving caller-supplied path.",
        argument_roles=["filepath"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-path-zip-extract-slip",
        function="zip slip during archive extract",
        call_regex=r"\bfilepath\.\s*Join\s*\([^,)]+,\s*[^.)]+\.\s*Name\b",
        description="Joining base path with entry.Name without sanity-checking traversal.",
        argument_roles=[],
        extensions=_GO,
        severity="high",
    ),
]

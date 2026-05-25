"""Java — Path Traversal sinks (CWE-22)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "path_traversal"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-path-new-file",
        function="new File(dynamic path)",
        call_regex=r"\bnew\s+File\s*\(",
        description="Creating File with caller-controlled path.",
        argument_roles=["pathname"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-paths-get",
        function="Paths.get(userInput)",
        call_regex=r"\bPaths\s*\.\s*get\s*\(",
        description="java.nio.file.Paths.get with dynamic segments.",
        argument_roles=["first", "more"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-files-readallbytes",
        function="Files.readAllBytes / readAllLines / newInputStream",
        call_regex=r"\bFiles\s*\.\s*(?:readAllBytes|readAllLines|readString|newBufferedReader|newInputStream|lines)\s*\(",
        description="NIO Files read APIs with dynamic path.",
        argument_roles=["path"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-files-write",
        function="Files.write / newOutputStream",
        call_regex=r"\bFiles\s*\.\s*(?:write|writeString|newBufferedWriter|newOutputStream)\s*\(",
        description="NIO Files write APIs with dynamic path.",
        argument_roles=["path", "bytes"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-files-delete",
        function="Files.delete / deleteIfExists",
        call_regex=r"\bFiles\s*\.\s*(?:delete|deleteIfExists)\s*\(",
        description="Delete with caller-supplied path.",
        argument_roles=["path"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-fileinputstream",
        function="new FileInputStream / FileOutputStream / RandomAccessFile",
        call_regex=r"\bnew\s+(?:FileInputStream|FileOutputStream|RandomAccessFile|FileReader|FileWriter)\s*\(",
        description="Classic file I/O constructors with dynamic path.",
        argument_roles=["name"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-spring-resource",
        function="new ClassPathResource / FileSystemResource(value)",
        call_regex=r"\bnew\s+(?:ClassPathResource|FileSystemResource|UrlResource|PathResource)\s*\(",
        description="Spring Resource ctor with dynamic location.",
        argument_roles=["location"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-path-zip-getentry-traversal",
        function="ZipEntry/ZipFile traversal (zip slip)",
        call_regex=r"\bnew\s+File\s*\(\s*[^,)]+,\s*[^)]+\.\s*getName\s*\(\s*\)",
        description="Building extraction path from zip entry name — zip slip pattern.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
]

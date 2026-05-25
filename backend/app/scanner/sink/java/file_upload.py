"""Java — Arbitrary File Upload sinks (CWE-434)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_upload"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-upload-multipart-transferto",
        function="MultipartFile.transferTo(File)",
        call_regex=r"\.\s*transferTo\s*\(",
        description="Spring MultipartFile.transferTo persists upload at caller path.",
        argument_roles=["dest"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-upload-getoriginalfilename",
        function="MultipartFile.getOriginalFilename → File path",
        call_regex=r"\.\s*getOriginalFilename\s*\(",
        description="Using attacker-supplied original filename as part of destination path.",
        argument_roles=[],
        extensions=_JAVA,
        severity="high",
    ),
    SinkRule(
        id="java-upload-commons-fileupload-write",
        function="DiskFileItem.write(File)",
        call_regex=r"\bDiskFileItem\b[\s\S]{0,80}\.\s*write\s*\(",
        description="commons-fileupload DiskFileItem.write with dynamic path.",
        argument_roles=["file"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-upload-jakarta-part-write",
        function="jakarta.servlet.http.Part.write",
        call_regex=r"\.\s*write\s*\(",
        description="Servlet 3+ Part.write to disk; verify filename validation.",
        argument_roles=["fileName"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-upload-fos-copy",
        function="Files.copy(stream, target)",
        call_regex=r"\bFiles\s*\.\s*copy\s*\(",
        description="Files.copy from uploaded stream to disk.",
        argument_roles=["in", "target", "options"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
]

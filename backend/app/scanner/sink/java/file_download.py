"""Java — Arbitrary File Download sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "file_download"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-dl-fileinputstream-pipe",
        function="FileInputStream(path) → response",
        call_regex=r"\bnew\s+FileInputStream\s*\(",
        description="FileInputStream with dynamic path before write to response.",
        argument_roles=["name"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-dl-fileutils-copytostream",
        function="IOUtils.copy / FileUtils.copyFileToStream",
        call_regex=r"\b(?:IOUtils|FileUtils)\s*\.\s*(?:copy|copyFile|copyFileToStream|write)\s*\(",
        description="Apache IO copy from File to response stream.",
        argument_roles=["src", "dst"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-dl-resourceloader-getresource",
        function="ResourceLoader.getResource(url)",
        call_regex=r"\.\s*getResource\s*\(",
        description="Spring ResourceLoader.getResource — file:// / classpath: schemes.",
        argument_roles=["location"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-dl-content-disposition-from-param",
        function="Content-Disposition built from request param",
        call_regex=r"setHeader\s*\(\s*\"Content-Disposition\"",
        description="Filename from request parameter reflected into header — also CRLF risk.",
        argument_roles=["name", "value"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
]

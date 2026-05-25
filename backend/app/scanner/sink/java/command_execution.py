"""Java — Command Execution sinks (CWE-78)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "command_execution"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-cmd-runtime-exec",
        function="Runtime.getRuntime().exec(...)",
        call_regex=r"\bRuntime\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\.\s*exec\s*\(\s*[\w\"]",
        description="Runtime.exec invokes OS command; arrays still suffer argv injection on Windows.",
        argument_roles=["command"],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-cmd-processbuilder",
        function="new ProcessBuilder(...)",
        call_regex=r"\bnew\s+ProcessBuilder\s*\(",
        description="ProcessBuilder constructed with user-controlled args.",
        argument_roles=["command"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-cmd-processbuilder-start",
        function="ProcessBuilder.command(...).start()",
        call_regex=r"\.\s*command\s*\([^)]*\)\s*\.\s*start\s*\(",
        description="ProcessBuilder.command(...).start chain.",
        argument_roles=["command"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-cmd-groovy-execute",
        function="String.execute() / 'cmd'.execute()",
        call_regex=r"\.\s*execute\s*\(\s*\)",
        description="Groovy String.execute() spawns a process (Jenkins / Grails).",
        argument_roles=[],
        extensions=[".groovy", ".gradle"],
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-cmd-scripting-eval",
        function="ScriptEngine.eval(code)",
        call_regex=r"\.\s*eval\s*\(",
        description="javax.script ScriptEngine evaluating arbitrary script — often RCE.",
        argument_roles=["script"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-cmd-velocity-evaluate",
        function="Velocity.evaluate(...)",
        call_regex=r"\bVelocity\s*\.\s*evaluate\s*\(",
        description="Velocity evaluate with user-controlled template = RCE.",
        argument_roles=["context", "writer", "logTag", "instring"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-cmd-jython-exec",
        function="PythonInterpreter.exec",
        call_regex=r"\bPythonInterpreter[\s\S]{0,40}\.\s*exec\s*\(",
        description="Jython embedded Python exec with user-controlled code.",
        argument_roles=["code"],
        extensions=_JAVA,
        severity="critical",
    ),
]

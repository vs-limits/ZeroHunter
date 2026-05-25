"""Java — Code Execution / Class Loading sinks (CWE-94)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "code_execution"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-code-classloader-loadclass",
        function="ClassLoader.loadClass(name)",
        call_regex=r"\.\s*(?:loadClass|defineClass|findClass)\s*\(",
        description="Loading class with caller-controlled name.",
        argument_roles=["name"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-code-class-forname",
        function="Class.forName(userValue)",
        call_regex=r"\bClass\s*\.\s*forName\s*\(",
        description="Class.forName loads class by name.",
        argument_roles=["className"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-code-reflection-invoke",
        function="Method.invoke(target, args)",
        call_regex=r"\.\s*invoke\s*\(",
        description="java.lang.reflect Method.invoke with dynamic method.",
        argument_roles=["obj", "args"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-code-mvel-eval",
        function="MVEL.eval(expression)",
        call_regex=r"\bMVEL\s*\.\s*(?:eval|evalToString|compileExpression)\s*\(",
        description="MVEL expression evaluation = RCE on attacker-controlled input.",
        argument_roles=["expression"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-code-ognl-getValue",
        function="Ognl.getValue / setValue",
        call_regex=r"\bOgnl\s*\.\s*(?:getValue|setValue|parseExpression)\s*\(",
        description="OGNL expression — Struts2 historical RCE class.",
        argument_roles=["expression"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-code-spel-parser",
        function="SpelExpressionParser.parseExpression",
        call_regex=r"\bparseExpression\s*\(",
        description="Spring SpEL expression from user input.",
        argument_roles=["expression"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-code-jexl-evaluate",
        function="JexlEngine.createExpression / evaluate",
        call_regex=r"\bJexl(?:Engine|Builder)?[\s\S]{0,40}\.\s*(?:createExpression|createScript|evaluate)\s*\(",
        description="Apache JEXL evaluating expression from request.",
        argument_roles=["expression"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-code-bsf-engine",
        function="BSFManager.exec / eval",
        call_regex=r"\bBSFManager[\s\S]{0,40}\.\s*(?:exec|eval)\s*\(",
        description="Apache BSF eval of attacker-supplied script.",
        argument_roles=["lang", "source", "lineNo", "columnNo", "expr"],
        extensions=_JAVA,
        severity="critical",
    ),
    SinkRule(
        id="java-code-nashorn-eval",
        function="ScriptEngineManager('nashorn').eval",
        call_regex=r"getEngineByName\s*\(\s*\"(?:nashorn|js|javascript|graal\.js)\"",
        description="Nashorn engine evaluating arbitrary JS.",
        argument_roles=["name"],
        extensions=_JAVA,
        severity="critical",
    ),
]

# Java — Code Execution / Expression Injection (CWE-94)

## Sink inventory
- `ScriptEngine.eval(script)` (Nashorn, GraalJS, Jython, JRuby).
- Spring SpEL `parser.parseExpression(expr)` / `getValue` /
  `setValue`.
- OGNL `Ognl.getValue` / `parseExpression`.
- MVEL `MVEL.eval`.
- Apache JEXL `JexlEngine.createExpression / evaluate`.
- BSF `BSFManager.exec / eval`.
- Velocity `Velocity.evaluate` with user template = template
  injection → RCE.
- `Class.forName(name)` / `ClassLoader.loadClass(name)` with
  attacker name.
- `Runtime.exec` / `ProcessBuilder` — see command_execution skill.

## Decision flow

1. The expression / script must contain attacker-controlled bytes.
2. Sandboxes:
   - Nashorn: `--no-java` / restricted ScriptEngine factory.
   - SpEL: `SimpleEvaluationContext` instead of
     `StandardEvaluationContext` makes it safer.
   - OGNL: Struts 2 added type-tightening filters; many bypasses
     historically.
3. Confirm payload reaches the sink unfiltered.

## Tool hints

- `tldr__tldr_extract` on the dispatcher and on the script-engine
  factory configuration.
- `ripgrep__search "StandardEvaluationContext"` /
  `"setAllowedClasses"`.

## POC template

SpEL with StandardEvaluationContext:
```
T(java.lang.Runtime).getRuntime().exec('id')
```

OGNL (Struts 2):
```
%{(#a=@java.lang.Runtime@getRuntime().exec({'id'}))}
```

## Fix recommendations
1. Replace expression evaluation with structured parameters.
2. If expression evaluation must stay, use a sandboxed context
   (SpEL `SimpleEvaluationContext`, restricted SecurityManager
   policy where still supported).
3. Validate expressions against an allowlist of known-safe
   templates.

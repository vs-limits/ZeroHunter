# Generic Vulnerability Audit Skill

This is the fallback knowledge module used when no language-specific
skill exists for a `(language, vulnerability_type)` pair.

## How to judge whether a flagged sink is exploitable

1. **Identify the source.** Trace the variable(s) feeding the sink
   argument back through the enclosing function. The source must be
   *attacker-controlled* (HTTP request, file upload, IPC payload,
   environment variable in a privileged context, etc.). If the value
   is an internal constant, a configuration key the user can't
   influence, or a value already validated against an allowlist, the
   finding is a false positive.

2. **Trace the path.** Confirm there is a *reachable* control-flow
   path from the source to the sink. Look for:
   - Early `return` / `throw` that aborts before the sink
   - Explicit authorization checks (`is_admin`, role guards)
   - Type / length / format validation that constrains the value

3. **Defeat the filters.** If any filter exists, ask "can I bypass
   it?" Examples of bypassable filters:
   - Length-only checks
   - Blacklist regex that misses unusual encodings (URL-encoded,
     double-encoded, Unicode homoglyphs, null-byte injection)
   - Client-side validation that can be skipped via Burp / curl
   - "strip tags" that doesn't normalize first

4. **Confirm impact.** What can the attacker actually achieve? Read
   files? Run commands? Escalate privileges? If the sink merely
   causes a DoS or a benign error, downgrade severity.

## When to call MCP tools

If the audit_pack lacks the source, the enclosing function body, or
the call chain is incomplete:

- Use `tldr__tldr_extract` to fetch the function definition.
- Use `tldr__tldr_calls` / `tldr__tldr_impact` to widen the call
  graph.
- Use `ripgrep__search` with a tight regex to find related callers or
  configuration that gates the path.

Only stop calling tools when you are confident in a verdict.

## Verdict rules

- `vulnerable` — full source→sink path exists, no effective filter,
  impact is concrete. Confidence ≥ 0.8.
- `uncertain` — path *might* exist but you need a file / function /
  configuration that wasn't provided. List exactly what is missing.
- `safe` — call the specific guard (function name + file + line) that
  blocks exploitation. Don't guess.

Reject `vulnerable` whenever you cannot point to a concrete
attacker-controlled source.

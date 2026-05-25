# PHP — Command Execution Audit Skill (CWE-78)

## Sink inventory (ranked by danger)

1. `system`, `passthru`, `shell_exec`, `exec`, ``backtick`` operator
   — direct shell, full RCE with argument injection.
2. `proc_open`, `popen` — shell unless explicit `array` argv form
   with no shell interpretation.
3. `pcntl_exec` — does NOT use the shell; only argv injection.
4. `mail()` 5th argument — passed to `sendmail` and can carry
   `\\\` flags.
5. `mb_send_mail` 5th arg — same risk profile.

## What makes a hit exploitable

- The first argument (the command string) contains a non-escaped
  variable derived from user input, OR
- An array of arguments is built from user input WITHOUT
  `escapeshellarg` per element.

## Sanitizers and their gotchas

- `escapeshellcmd`: escapes shell metacharacters from the *whole
  command* but does **not** escape per-argument quoting. Bypass:
  inject an option flag (`-oQueueDirectory=/tmp/x`) when the command
  itself is unprotected.
- `escapeshellarg`: safe per argument. **Bypass**: not applied to
  every concatenated piece; argv injection still possible if the
  attacker controls a flag prefix.
- `preg_replace('/[^a-zA-Z0-9]/', '', $x)` allowlist: safe if the
  whitelist is correct, but verify it isn't applied after the
  concatenation.

## Tool hints

- `ripgrep__search` for `escapeshellarg` / `escapeshellcmd` in the
  chain.
- Trace the variable: if it ends in `intval` / `(int)` / hard
  enum check, downgrade to `safe`.
- For mail()'s 5th param: confirm any `-X`-style options are
  whitelisted.

## POC templates

Shell-command injection: `?file=x;id` against
`exec("convert ".$_GET['file']);`.
Argv injection (escapeshellarg used per-arg but flag injection):
`?id=--option=evil` when `$cmd = "git log " . escapeshellarg($id);`.

## Fix recommendations

1. Prefer language APIs that don't shell-out (e.g. `glob()`,
   `mkdir()` instead of `system("mkdir ...")`).
2. Use the argv form of `proc_open` with `bypass_shell` true on
   Windows, no shell on Unix; never compose a shell string.
3. If a shell call is unavoidable, ALWAYS pass user data via
   `escapeshellarg($x)` and prepend `--` to terminate option
   parsing.

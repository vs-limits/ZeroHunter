# Python — Command Execution Audit Skill (CWE-78)

## Sink inventory

- `os.system($x)` — full shell, full RCE.
- `subprocess.Popen(cmd, shell=True)` — same.
- `subprocess.call/run/check_output(cmd, shell=True)` — same.
- `subprocess.Popen(cmd_list)` — safe if `cmd_list` is a list; argv
  injection only if an attacker controls the first element.
- `os.popen($x)` — invokes `/bin/sh`.
- `commands.getoutput` (Python 2) — same shell risk.
- `eval` / `exec` / `compile` / `__import__` — see code_execution.

## Decision flow

1. Is `shell=True`? If yes, look at the command string composition.
2. If a list is passed, look at how each element is built — most
   safe but verify no `["bash", "-c", $user]` pattern.
3. Check pre-validation: `re.match(r'^[a-z0-9_-]+$', val)` is safe
   if the regex is anchored and applied *before* concatenation.

## Sanitizers and bypass

- `shlex.quote($x)` — safe for posix shells; **does not** protect
  Windows `cmd.exe`.
- `pipes.quote` — same as shlex.quote.
- `subprocess` with list form — safe but adopt `--` argument
  separator to neutralize option injection.

## Tool hints

- `ripgrep__search "shell=True"` to map every risky call.
- `tldr__tldr_extract` on the helper that builds the command.

## POC templates

`?host=127.0.0.1; id` against `subprocess.run(f"ping {host}", shell=True)`.
Argv injection: `?branch=--upload-pack=touch /tmp/pwned` against
`subprocess.run(["git", "clone", "--branch", branch, repo])`.

## Fix recommendations

1. Default to `shell=False` and pass argument lists.
2. Add `--` between option args and user values to terminate option
   parsing.
3. If the user must provide a flag, validate against a strict
   allowlist.

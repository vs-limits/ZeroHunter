# JavaScript / Node — Command Execution Audit Skill (CWE-78)

## Sink inventory

- `child_process.exec($cmd, callback)` — shell, RCE.
- `child_process.execSync($cmd)` — same.
- `child_process.spawn(...)` / `execFile(...)` with `shell: true` —
  same.
- `child_process.spawn("sh", ["-c", $x])` — explicit shell.
- `eval`, `new Function`, `vm.runIn*` — code execution.
- `shelljs.exec($cmd)` — shell wrapper.
- `execa($cmd)` with string-form cmd.

## Safe argv form

`child_process.execFile("bin", [arg1, arg2])` is safe from shell
meta-character injection, but watch:
- Argv injection if the program respects flags (`--upload-pack`,
  `-X POST -d ...`).
- Path injection if `bin` is constructed from user input.

## Decision flow

1. `shell: true` (explicit or implicit via `exec`) + dynamic
   command string = **vulnerable**.
2. Argv form, but user controls argv[0] (binary path) = vulnerable
   (path takeover).
3. Argv form, user controls argv[1+] = depends; look for `--`
   separator and known dangerous flags.

## Tool hints

- `ripgrep__search "shell.*true"` to find risky spawn options.
- `tldr__tldr_extract` on the helper that runs the command.

## POC templates

`exec(`ping ${host}`)` with `?host=8.8.8.8;id`.
`spawn("git", ["clone", "--branch", branch])` with
`?branch=--upload-pack=touch /tmp/pwned`.

## Fix recommendations

1. Use `execFile` / `spawn` with argv array.
2. Prepend `--` to terminate option parsing for git/curl/etc.
3. Validate user-controlled flag values against an allowlist.

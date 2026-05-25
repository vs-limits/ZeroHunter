# PHP — File Inclusion Audit Skill (LFI/RFI, CWE-98)

## Sink inventory
- `include`, `include_once`, `require`, `require_once`
- Class autoload registered via `spl_autoload_register` with
  attacker-influenced class names

## Why this is a top-tier RCE primitive

If the include path contains user-controlled data with no allowlist:

- **LFI → RCE**:
  - Include uploaded file (any extension), interpreted as PHP.
  - `php://filter/convert.base64-encode/resource=index` to read
    source.
  - `data://text/plain,<?php phpinfo(); ?>` (RFI variant if
    `allow_url_include=On`).
  - Log poisoning: write PHP into `/var/log/apache2/access.log`
    via `User-Agent`, then include.
  - `phar://` to chain into deserialization.

## Decision flow

1. Find the source of the path argument.
2. Look for normalization (`basename`, `pathinfo['filename']`,
   `realpath`) and the *base directory* check.
3. **Critical**: confirm the result of normalization is then
   compared against an allowlist (an explicit `in_array`, or
   `str_starts_with($real, $base)`), not just a regex.
4. Confirm `allow_url_include` is not turned on in php.ini.

## Common bypasses

- `basename` strips directory components but keeps query strings;
  combined with `allow_url_include=On` still RFI-able.
- `str_replace("../", "", $x)` collapses one level — use
  `....//` to defeat.
- Hardcoded `.php` suffix appended by the developer — but
  `php://filter` and `phar://` don't need a real extension.

## Tool hints

- `ripgrep__search` for `pathinfo` / `realpath` / `basename` /
  `dirname` in the chain.
- `tldr__tldr_extract` on `php.ini` parser if config-driven.

## POC template

`?page=php://filter/convert.base64-encode/resource=/var/www/html/config`
`?page=/var/log/apache2/access.log` after sending request with
`<?php system($_GET['c']);?>` in `User-Agent`.

## Fix recommendations

1. Strict allowlist: map user input via a `pages` array, never
   use it directly.
2. Disable `allow_url_include` and `allow_url_fopen` in production
   php.ini.
3. Strip wrapper schemes manually if you really must accept
   filenames: reject anything matching `:\/\/`.

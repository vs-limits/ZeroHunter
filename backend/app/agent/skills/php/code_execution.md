# PHP — Code Execution Audit Skill (CWE-94/CWE-95)

## Sink inventory
- `eval($x)` — string evaluated as PHP code.
- `create_function($args, $body)` (removed in PHP 8 but still seen).
- `preg_replace($pattern, $replacement, $subject)` with `/e`
  modifier (deprecated since 5.5, removed 7.0; legacy code).
- `assert($x)` when `$x` is a string and `assert.active = 1` (legacy).
- `call_user_func` / `array_map` / `usort` etc. with first arg from
  attacker (RCE via "system" string).

## Decision flow

1. Trace the *first* argument back to source.
2. Look for allowlists (whitelist of callable strings).
3. For `eval`/`create_function`: any string concatenation involving
   attacker data is **vulnerable** unless escaped via
   `var_export($x, true)` AND `$x` is provably typed.

## Tool hints

- `ripgrep__search` for `is_callable` / `function_exists` around
  the sink — these are *not* sufficient (anything declared, e.g.
  `system`, is callable).
- `tldr__tldr_extract` on the dispatcher function.

## POC template
```php
?cb=system    // dispatched to call_user_func($_GET['cb'], $_GET['x'])
&x=id
```

## Fix recommendations

1. Replace `eval` with structured data + a strict allowlist of
   actions.
2. For `call_user_func` dispatchers, validate callable string
   against a hard map.
3. Migrate `preg_replace` `/e` calls to `preg_replace_callback`.

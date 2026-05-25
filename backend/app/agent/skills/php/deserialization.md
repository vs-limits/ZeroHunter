# PHP — Deserialization Audit Skill (CWE-502)

## Sink inventory
- `unserialize($x)` — classic native deserialization, exploited via
  POP (property-oriented programming) gadget chains.
- `phar://` wrappers passed to file functions — implicitly trigger
  unserialize on the metadata segment.
- `Symfony\Component\Serializer` with attacker-controlled type
  argument.
- `Laravel`/`Doctrine` cache layers that round-trip `unserialize`
  on cache values.

## Conditions for exploitability

1. The deserialized payload must contain magic methods (`__wakeup`,
   `__destruct`, `__toString`, `__call`) reachable from autoload
   classes available at run time.
2. A gadget chain must exist that turns one of those magic methods
   into a sensitive operation (file write, SQL, system call). The
   classic gadget chains live in third-party packages — even if the
   target app doesn't use them, Composer may load them.
3. Attacker controls the *exact bytes* — i.e. they reach the
   `unserialize` call directly, not after a JSON round-trip.

## Heuristic to use during audit

- If `unserialize` consumes `$_COOKIE`, `$_POST`, or a raw HTTP
  body, treat as **vulnerable** unless `JsonSerializable` /
  `__wakeup` returning safe primitives is in place.
- If it consumes data signed with HMAC and the signature is
  verified *before* unserialize, treat as **safe**. Use
  `tldr__tldr_extract` to verify the order of operations.

## Phar deserialization

When you see `file_exists($x)`, `fopen($x)`, etc., with attacker
control over `$x`, check whether `$x` can begin with `phar://`. If
PHP < 8.0 or `phar.readonly = Off`, this triggers unserialize on
phar metadata = same gadget chains.

## Tool hints

- `ripgrep__search "phar://"` in the repo: any allowlist check?
- `tldr__tldr_extract` on the controller to see if there's a
  signature check (`hash_equals(hash_hmac(...), $sig)`).

## POC template

1. Identify a gadget class with dangerous magic method.
2. Build a PHP class in your own environment matching the gadget's
   public properties, serialize an instance, base64-encode.
3. Send via the input that reaches `unserialize`.

## Fix recommendations

1. Don't use `unserialize` on untrusted input. Replace with
   `json_decode` + explicit schema validation.
2. If unserialize is unavoidable, sign payloads with HMAC and
   verify *before* unserialize.
3. Provide an `allowed_classes` whitelist:
   `unserialize($x, ['allowed_classes' => ['SafeDTO']])`.

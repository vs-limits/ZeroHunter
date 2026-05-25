# PHP — XSS Audit Skill (CWE-79)

## Source taxonomy
- Reflected: data from `$_GET`/`$_POST`/`$_COOKIE`/`$_REQUEST`/
  `$_SERVER` directly rendered back in the response.
- Stored: data persisted to DB / file / cache, later rendered.
- DOM: server hands attacker-controlled JSON/HTML to JS that writes
  to `innerHTML`, `eval`, etc. (cross-check with JS skill).

## Sink patterns

| Pattern | Verdict |
|---|---|
| `echo $_GET['x'];` | vulnerable, reflected |
| `printf("<div>%s</div>", $name);` with `$name = $_POST['name']` | vulnerable |
| `<?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?>` | safe in HTML body context |
| `<?= htmlspecialchars($url) ?>` inside `<a href="…">` | maybe vulnerable (javascript:URL) — see context rules |
| Twig `{{ name }}` (default escape) | safe |
| Twig `{{ name|raw }}` | vulnerable unless `name` is provably HTML-clean |
| Blade `{!! $x !!}` | vulnerable unless `$x` is HTML-clean |

## Context-aware encoding

`htmlspecialchars` is only safe in an HTML *body* / attribute-value
context with quotes. **Unsafe contexts**:
- Inside `<script>...</script>` blocks — needs JSON-encode +
  context-specific escaping.
- Inside `style="..."` — CSS escape needed.
- As a URL: must use `urlencode` plus allowlist the scheme
  (`http`, `https`, `mailto`).
- Unquoted attribute (`<input value=$x>`) — htmlspecialchars
  without `ENT_QUOTES` is bypassable via space-separated payloads.

## Bypass classes worth checking

- `strip_tags` removes tags but leaves event handler strings; later
  HTML composition can re-introduce them.
- `htmlentities` without `ENT_QUOTES` leaves `'`/`"` unescaped.
- WAF-style regex filters (`<script`, `javascript:`) — bypass with
  `<svg onload=…>`, `<img onerror=…>`, mixed-case, vbscript, data
  URIs.

## Tool hints

- `tldr__tldr_extract` on the controller to read `$_GET`/$_POST
  bindings.
- `ripgrep__search` for `htmlspecialchars` / `e()` (Laravel) /
  `escape` / `striptags` in the chain to confirm encoding.
- Inspect view files (`.twig`, `.phtml`, `.blade.php`) named after
  the controller method.

## POC template

Body context: `?x=<svg onload=alert(1)>`
Attribute context (no quotes): `?x= onmouseover=alert(1) x`
URL context: `?next=javascript:alert(1)` rendered in `href`.

## Fix recommendations

1. Use the template engine's auto-escape and avoid `|raw` / `{!! !!}`.
2. Pick the escape function by context: `htmlspecialchars` for HTML,
   `json_encode($v, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)`
   inside `<script>`, `urlencode` + scheme allowlist in URLs.
3. Set `Content-Security-Policy: default-src 'self'; script-src 'self'`
   to neutralize stored XSS surfaces.

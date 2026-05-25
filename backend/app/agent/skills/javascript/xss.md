# JavaScript / Node — XSS Audit Skill (CWE-79)

## DOM XSS sinks (browser)

- `element.innerHTML = $x`
- `element.outerHTML = $x`
- `element.insertAdjacentHTML(pos, $x)`
- `document.write/writeln($x)`
- `$('selector').html($x)` (jQuery)
- `eval`, `setTimeout(string, ...)`, `new Function(string)` —
  also code execution
- `element.src = $x` for `<script>` / `<iframe>` with untrusted
  values; `location = $x` for `javascript:` URLs

## Framework-specific bypass sinks

- React: `dangerouslySetInnerHTML={{ __html: $x }}`
- Vue: `v-html="$x"`
- Angular: `DomSanitizer.bypassSecurityTrustHtml($x)` and family
- Svelte: `{@html $x}`

## Node-side (response XSS)

- `res.send`, `res.write`, `res.end` with a string containing HTML
- `res.render(view, { unsafe: $x })` when the template uses raw
  output (EJS `<%- $x %>`, Handlebars `{{{ $x }}}`)

## Source taxonomy
- Reflected: `req.query`, `req.params`, `req.body`
- Stored: read from DB then rendered
- DOM source: `location.hash`, `location.search`, `document.cookie`,
  `window.name`, `postMessage` data

## Decision flow

1. Trace the value: must originate from a source.
2. Encoding: was it run through `escape-html`, `lodash.escape`,
   `he.encode`, JSX auto-escape? If yes and the context is HTML
   body / quoted attribute, mark **safe**.
3. Context mismatch: encoding for HTML body but value lands in a
   `<script>` block → still vulnerable.
4. CSP: `Content-Security-Policy: default-src 'self'; script-src
   'self'` reduces impact but doesn't fix DOM XSS that uses
   inline event handlers from same-origin.

## Tool hints

- `ripgrep__search "innerHTML"` to enumerate sinks.
- `tldr__tldr_extract` on the template / handler.
- Look for `DOMPurify.sanitize($x)` — its presence usually
  suffices.

## POC templates

DOM: `?q=<img src=x onerror=alert(1)>`
React/Vue: ` "><script>alert(1)</script>` (only when the
`dangerouslySetInnerHTML`/`v-html` directive is reached).
React safe context: JSX auto-escapes children; props that are not
HTML props need separate encoding.

## Fix recommendations

1. Prefer textContent / framework-default-escape rendering.
2. If raw HTML is required, use DOMPurify with a tight allowlist.
3. Use `Trusted Types` policy on modern browsers to ban risky
   sinks.

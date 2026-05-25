# Python — SSTI Audit Skill (CWE-1336)

## Sink inventory

- Flask: `render_template_string(src, ...)` with attacker-supplied
  `src` — RCE via Jinja2 `{{ ''.__class__.__mro__[1].__subclasses__() ...}}`
- Jinja2: `Template(source)` / `Environment.from_string(source)`.
- Django: `Engine.from_string(src)`.
- Mako: `Template(text=src)`.
- Tornado: `Template(template_string=src)`.
- Chameleon: `PageTemplate(body=src)`.

## Exploitability test

If the attacker can put `{{ 7*7 }}` in input and see `49` in output,
SSTI confirmed; pivot to RCE via class introspection (`__mro__`,
`__subclasses__`, `os` import) on Jinja2/Mako without sandboxes, or
`config.update`/`request` leakage on Flask.

## Decision flow

1. The source MUST be attacker-controlled. If `src` is a constant
   path like `render_template("index.html", name=val)`, that's a
   **template-context** call, not SSTI — auto-escape applies and
   only XSS class issues remain.
2. `Environment(autoescape=False)` further worsens any SSTI to also
   produce XSS.

## Tool hints

- `tldr__tldr_extract` on the rendering helper to distinguish
  `render_template` vs `render_template_string`.
- `ripgrep__search "from_string"` / `"Template\("`.

## POC template

`?name={{config.__class__.__init_subclasses__.__globals__['os'].popen('id').read()}}`

For Django: `{% debug %}` to confirm template engine.

## Fix recommendations

1. Never compile templates from user input; use parameter
   substitution into a fixed template instead.
2. If unavoidable, use a sandboxed environment (Jinja2
   `SandboxedEnvironment` or `ImmutableSandboxedEnvironment`).
3. Enable autoescape globally.

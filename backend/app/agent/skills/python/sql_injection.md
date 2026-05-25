# Python — SQL Injection Audit Skill (CWE-89)

## Sources
- `request.args`, `request.form`, `request.json`, `request.cookies`
  (Flask)
- `request.GET`, `request.POST`, `request.body` (Django)
- `await request.json()`, path params (FastAPI/Starlette)
- CLI argparse / sys.argv when running privileged scripts

## Safe vs. unsafe patterns

| Pattern | Verdict |
|---|---|
| `cur.execute("SELECT ... WHERE x = %s" % val)` | vulnerable |
| `cur.execute("SELECT ... WHERE x = %s", (val,))` | safe (DB-API parameterized) |
| `cur.execute(f"WHERE x = {val}")` | vulnerable |
| `Model.objects.raw("WHERE x = " + val)` | vulnerable |
| `Model.objects.raw("WHERE x = %s", [val])` | safe |
| `sqlalchemy.text("WHERE x = :v").bindparams(v=val)` | safe |
| `sqlalchemy.text(f"WHERE x = {val}")` | vulnerable |
| `Session.execute(select(User).where(User.id == val))` | safe (Core/ORM) |

## ORM-specific gotchas

- Django `QuerySet.extra(where=[...])` — `where` items are raw SQL,
  even if `params` is parameterized.
- Django `RawSQL` expression — same risk.
- SQLAlchemy `text()` only parameterizes when bound; f-string
  composition breaks safety.
- ORM ORDER BY / GROUP BY: never parameterizable. Need allowlist.

## Tool hints

- `tldr__tldr_extract` on the controller to inspect parameter source.
- `ripgrep__search "execute\\(.*%s.*%"` to find legacy formatting.

## POC template
```
GET /api/items?id=1' OR '1'='1
```

## Fix recommendations
1. Always pass params as a second argument to DB-API `execute`.
2. For SQLAlchemy use Core/ORM expressions; for `text()` use
   `.bindparams()`.
3. For dynamic identifiers (column / table / ORDER BY), validate
   against a hard allowlist server-side.

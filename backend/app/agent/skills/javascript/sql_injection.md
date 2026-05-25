# JavaScript / Node — SQL Injection Audit Skill (CWE-89)

## Sink inventory
- `mysql`/`mysql2` `conn.query("...${$x}...")`
- `pg` `client.query("..." + $x)`
- `sqlite3` `db.run("..."+ $x)`
- `mongodb` find with `$where` containing user JS code
- Sequelize `sequelize.query(rawSql, ...)`
- Knex `knex.raw(rawSql, ...)`
- TypeORM `dataSource.query(rawSql)`
- Prisma `$queryRawUnsafe` / `$executeRawUnsafe`

## Safe vs. unsafe patterns

| Pattern | Verdict |
|---|---|
| `conn.query("WHERE id=?", [id])` | safe |
| `` conn.query(`WHERE id=${id}`) `` | vulnerable |
| `Sequelize.literal($x)` | vulnerable when `$x` is dynamic |
| `prisma.$queryRaw\`SELECT ... ${val}\`` | safe (tagged template) |
| `prisma.$queryRawUnsafe(`SELECT ${val}`)` | vulnerable |
| `knex('users').where({ id })` | safe |

## Bypass classes

- `mysql_real_escape_string` JS port: applies only to value
  contexts (quoted).
- Escaping by hand with `.replace(/'/g, "''")` — bypassable via
  backslash, unicode escapes; never sufficient on its own.

## Tool hints

- `tldr__tldr_extract` on the route handler.
- `ripgrep__search "queryRaw\\("` to enumerate raw-query sites.

## POC template

`?id=1' OR '1'='1`

## Fix recommendations

1. Always use the driver's parameterized form (`?` placeholders +
   array) or ORM query builder.
2. For Prisma keep using the tagged template `prisma.$queryRaw`
   helper; avoid `*Unsafe`.
3. Validate identifiers (`column`, `direction`) against an
   allowlist.

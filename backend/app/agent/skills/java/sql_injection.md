# Java — SQL Injection Audit Skill (CWE-89)

## Sink inventory
- `Statement.execute*` / `executeQuery` / `executeUpdate` with
  concatenated SQL.
- `PreparedStatement` constructed from concatenated SQL (safe only
  when SQL is a constant and values use `setXxx(idx, val)`).
- Spring `JdbcTemplate.query / update` with `String.format`'d SQL.
- Hibernate `Session.createQuery(hql)` / `createSQLQuery(sql)` /
  `createNativeQuery(sql)` with concatenated string.
- JPA `EntityManager.createNativeQuery`.
- MyBatis `${param}` substitution (raw); `#{param}` is safe.

## Decision flow

1. Find the SQL string. Is it a constant? Built via concatenation?
   StringBuilder? `String.format`?
2. If parameterized via `?` and values bound through `setXxx`, mark
   **safe**.
3. For HQL: column references in dynamic ORDER BY / GROUP BY are
   never parameterizable; need allowlist.

## MyBatis specifics
- `WHERE col = #{val}` -> parameter bind (safe).
- `WHERE col = ${val}` -> raw substitution (vulnerable).
- `<if test="...">` clauses are fine, but the body still controls
  substitution.

## Tool hints
- `ripgrep__search "createNativeQuery"` / `"executeQuery"` to find
  patterns; cross-reference with `String.format` / `+ ` concat.
- `tldr__tldr_extract` on the DAO method.

## POC template
`GET /api/items?id=1' OR '1'='1`

## Fix recommendations
1. Always use `PreparedStatement` with `?` and `setXxx`.
2. For HQL use named parameters `:name` and `setParameter`.
3. For MyBatis, switch every `${}` to `#{}` except identifier
   substitution that is validated against a hard allowlist.

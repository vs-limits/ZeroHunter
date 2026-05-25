# PHP — SQL Injection Audit Skill (CWE-89)

## Sources that feed PHP SQL sinks
- `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER` (notably
  `HTTP_HOST`, `HTTP_REFERER`, request URI fragments)
- `file_get_contents("php://input")`, JSON body parsed via
  `json_decode($input)`
- Values pulled from a previous database row only if the row itself
  was originally attacker-controlled (stored injection)

## Safe vs. unsafe sink patterns

| Pattern | Verdict |
|---|---|
| `mysqli_query($db, "SELECT ... WHERE x = $userId")` | vulnerable |
| `mysqli_query($db, "SELECT ... WHERE id=" . intval($_GET['id']))` | safe (intval casts to int) |
| `$pdo->prepare("SELECT ... WHERE x = ?")` + `$stmt->execute([$x])` | safe (parameterized) |
| `$pdo->prepare(sprintf("ORDER BY %s", $col))` | vulnerable (ORDER BY can't be parameterized) |
| `Doctrine\DBAL\Connection->executeQuery($sql, $params)` | safe iff `$sql` is a constant and untrusted data goes through `$params` |

## Sanitizers commonly seen — most are bypassable

- `mysql_real_escape_string` / `mysqli_real_escape_string`:
  *only* safe for values quoted in the query. **Bypass**: integer
  context (`WHERE id=$x`) without surrounding quotes still injects.
- `addslashes`: unsafe; ignores charset, vulnerable to multi-byte
  attacks (GBK-style).
- `htmlspecialchars`: not a SQL sanitizer; useless against injection.
- `intval` / `(int)` casts: safe for purely numeric columns.
- `preg_match('/^[a-z0-9_]+$/i', $name)`: safe for column / table
  names if the regex truly anchors and is whitelist-style.

## Identifier injection (column / table / ORDER BY)

PDO parameter binding only escapes *values*, never identifiers. If
the audit shows `ORDER BY $userSupplied` or `SELECT * FROM $table`,
look for an explicit allowlist:
```php
if (!in_array($col, ['id', 'name', 'created_at'])) { abort(); }
```
Absence of such an allowlist → vulnerable.

## Tool hints

- `ripgrep__search` for the sink variable to find where it's assigned.
- `tldr__tldr_extract` on the enclosing function to see all branches.
- If the chain runs through Doctrine / Eloquent / Symfony forms,
  look for a `validate` / `assert` rule near the controller; absence
  is a yellow flag, not proof of vulnerability.

## POC template

For a typical `GET /endpoint?id=<payload>`:
```
GET /endpoint?id=1%20OR%201%3D1-- HTTP/1.1
```
Adjust per database flavour: `'' OR 1=1--` for SQLite/MySQL with
quoted-string context; UNION-based or time-based blind for
constrained outputs.

## Fix recommendations

1. Replace direct string concatenation with PDO prepared statements
   (`$pdo->prepare(... ?...)` + `execute([...])`), or use the ORM's
   parameterized query API.
2. For identifier-as-input columns, validate against a hard
   allowlist *server-side*.
3. Apply principle of least privilege on the DB user (no `DROP`,
   `FILE`, etc.).

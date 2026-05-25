"""Go — SQL Injection sinks (CWE-89)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "sql_injection"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-sql-db-query",
        function="db.Query / QueryRow / QueryContext",
        call_regex=r"\.\s*(?:Query|QueryRow|QueryContext|QueryRowContext)\s*\(",
        description="database/sql Query* with fmt.Sprintf'd SQL.",
        argument_roles=["query", "args"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"fmt\.Sprintf", r"\+\s*\w", r"%[sv]"],
    ),
    SinkRule(
        id="go-sql-db-exec",
        function="db.Exec / ExecContext",
        call_regex=r"\.\s*Exec(?:Context)?\s*\(",
        description="database/sql Exec with formatted SQL string.",
        argument_roles=["query", "args"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"fmt\.Sprintf", r"\+\s*\w", r"%[sv]"],
    ),
    SinkRule(
        id="go-sql-sqlx-named",
        function="sqlx.NamedExec / NamedQuery (raw)",
        call_regex=r"\.\s*(?:NamedExec|NamedQuery|Get|Select|MustExec)\s*\(",
        description="sqlx convenience methods with fmt.Sprintf'd query.",
        argument_roles=["query", "arg"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-sql-gorm-raw",
        function="gorm.DB.Raw / Exec",
        call_regex=r"\.\s*(?:Raw|Exec)\s*\(",
        description="GORM Raw/Exec with concatenated/formatted SQL.",
        argument_roles=["sql", "values"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-sql-gorm-where-format",
        function="gorm Where with fmt.Sprintf",
        call_regex=r"\.\s*Where\s*\(\s*fmt\.Sprintf",
        description="GORM Where clause built via fmt.Sprintf.",
        argument_roles=["query", "args"],
        extensions=_GO,
        severity="high",
    ),
    SinkRule(
        id="go-sql-sqlc-no-params",
        function="generated sqlc method passed string",
        call_regex=r"db\.\s*Query(?:Row)?\s*\(\s*ctx\s*,\s*fmt\.Sprintf",
        description="Calling sqlc-style helper with fmt.Sprintf — defeats prepared statement.",
        argument_roles=["ctx", "query"],
        extensions=_GO,
        severity="high",
    ),
]

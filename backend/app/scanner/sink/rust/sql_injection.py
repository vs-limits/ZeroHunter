"""Rust — SQL Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "sql_injection"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-sql-rusqlite-execute",
        function="rusqlite::Connection.execute / query",
        call_regex=r"\.\s*(?:execute|execute_batch|query|query_map|query_row|prepare)\s*\(",
        description="rusqlite execute/query with format!()'d SQL.",
        argument_roles=["sql", "params"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"format!", r"\.to_string\(\)", r"\+\s*&?\w"],
    ),
    SinkRule(
        id="rs-sql-postgres-execute",
        function="postgres::Client.execute / query",
        call_regex=r"\.\s*(?:execute|query|query_one|query_opt|simple_query|batch_execute)\s*\(",
        description="rust-postgres execute with formatted SQL.",
        argument_roles=["statement", "params"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"format!", r"\+\s*&?\w"],
    ),
    SinkRule(
        id="rs-sql-sqlx-raw-query",
        function="sqlx::query(&format!(...))",
        call_regex=r"\bsqlx\s*::\s*query(?:_as|_unchecked|_scalar)?\s*\(",
        description="sqlx::query with non-macro string built from format!.",
        argument_roles=["sql"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"format!", r"\+\s*&?\w"],
    ),
    SinkRule(
        id="rs-sql-diesel-sql-query",
        function="diesel::sql_query(format!(...))",
        call_regex=r"\bdiesel\s*::\s*sql_query\s*\(",
        description="diesel::sql_query takes raw SQL string.",
        argument_roles=["query"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-sql-mysql-prep",
        function="mysql::Conn.prep / exec",
        call_regex=r"\.\s*(?:prep|exec|exec_drop|exec_iter|exec_first|query|query_drop|query_first|query_iter)\s*\(",
        description="mysql crate execute with formatted SQL.",
        argument_roles=["query", "params"],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
]

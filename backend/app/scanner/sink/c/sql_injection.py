"""C — SQL Injection sinks (CWE-89). MySQL / SQLite / libpq."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "sql_injection"

_C = [".c", ".h"]

RULES = [
    SinkRule(
        id="c-sql-mysql-query",
        function="mysql_query / mysql_real_query",
        call_regex=r"\bmysql_(?:real_)?query\s*\(",
        description="libmysqlclient mysql_query with formatted SQL.",
        argument_roles=["mysql", "stmt_str"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-sql-sqlite3-exec",
        function="sqlite3_exec / sqlite3_prepare(_v2)",
        call_regex=r"\bsqlite3_(?:exec|prepare(?:_v2|_v3)?|get_table)\s*\(",
        description="SQLite execute with concatenated SQL.",
        argument_roles=["db", "sql"],
        extensions=_C,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-sql-pq-exec",
        function="PQexec / PQexecParams (dynamic)",
        call_regex=r"\bPQ(?:exec|sendQuery)(?:Prepared|Params)?\s*\(",
        description="libpq exec functions with concatenated SQL.",
        argument_roles=["conn", "query"],
        extensions=_C,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="c-sql-oci-stmt-prepare",
        function="OCIStmtPrepare(... text ...)",
        call_regex=r"\bOCIStmtPrepare2?\s*\(",
        description="Oracle OCI prepare with concatenated SQL string.",
        argument_roles=["stmtp", "errhp", "stmt", "stmt_len"],
        extensions=_C,
        severity="high",
        require_dynamic=True,
    ),
]

"""C++ — SQL Injection sinks (Qt, ODB, MySQL Connector/C++)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "sql_injection"

_CPP = [".cpp", ".cc", ".cxx", ".cp", ".hpp", ".hh", ".hxx", ".h"]

RULES = [
    SinkRule(
        id="cpp-sql-qsqlquery-exec",
        function="QSqlQuery::exec(rawSql)",
        call_regex=r"\bQSqlQuery\b[\s\S]{0,40}\.\s*exec\s*\(",
        description="Qt QSqlQuery::exec with concatenated SQL string.",
        argument_roles=["query"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-sql-mysqlcppconn-execute",
        function="sql::Statement::execute / executeQuery",
        call_regex=r"\.\s*execute(?:Query|Update)?\s*\(",
        description="MySQL Connector/C++ Statement.execute with concatenated SQL.",
        argument_roles=["sql"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-sql-soci-statement",
        function="soci::statement << raw",
        call_regex=r"\bstatement\b[\s\S]{0,40}<<",
        description="SOCI statement with stream-built SQL containing user input.",
        argument_roles=[],
        extensions=_CPP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="cpp-sql-sqlite3-exec-cpp",
        function="sqlite3_exec(...)",
        call_regex=r"\bsqlite3_(?:exec|prepare(?:_v2|_v3)?)\s*\(",
        description="sqlite3 raw exec from C++.",
        argument_roles=["db", "sql"],
        extensions=_CPP,
        severity="high",
        require_dynamic=True,
    ),
]

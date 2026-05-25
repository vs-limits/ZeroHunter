"""Python — SQL Injection sinks (CWE-89)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "sql_injection"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-sql-cursor-execute",
        function="cursor.execute / executemany",
        call_regex=r"\.\s*execute(?:many)?\s*\(",
        description="DB-API execute / executemany; flagged when SQL uses string formatting.",
        argument_roles=["query", "params"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"%[sd]", r"\.format\s*\(", r"f['\"]", r"\+\s*(?:['\"]|[A-Za-z_])"],
    ),
    SinkRule(
        id="py-sql-sqlalchemy-text",
        function="sqlalchemy.text",
        call_regex=r"\btext\s*\(",
        description="sqlalchemy.text() with f-string / + concat is injectable.",
        argument_roles=["sql"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-sql-sqlalchemy-raw-execute",
        function="Engine/Connection.execute raw string",
        call_regex=r"\.\s*execute\s*\(\s*(?:f['\"]|['\"][^)]*%[sd])",
        description="SQLAlchemy execute with raw f-string / %s formatting.",
        argument_roles=["sql"],
        extensions=_PY,
        severity="high",
    ),
    SinkRule(
        id="py-sql-django-raw",
        function="QuerySet.raw / Model.objects.raw",
        call_regex=r"\.\s*raw\s*\(",
        description="Django QuerySet.raw with concatenated SQL is unsafe.",
        argument_roles=["raw_query", "params"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-sql-django-extra",
        function="QuerySet.extra",
        call_regex=r"\.\s*extra\s*\(",
        description="Django QuerySet.extra() takes raw SQL fragments.",
        argument_roles=["params"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-sql-asyncpg-execute",
        function="asyncpg fetch / execute",
        call_regex=r"\.\s*(?:fetch(?:val|row)?|execute|executemany)\s*\(",
        description="asyncpg execute / fetch* with f-string SQL.",
        argument_roles=["sql"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
]

"""TypeScript — ORM/Driver-specific SQL injection (TypeORM, Prisma)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "sql_injection"

_TS = [".ts", ".tsx"]

RULES = [
    SinkRule(
        id="ts-sql-typeorm-querybuilder-rawwhere",
        function="QueryBuilder.where(raw, params)",
        call_regex=r"\.\s*(?:where|andWhere|orWhere)\s*\(\s*`",
        description="TypeORM QueryBuilder where() with template literal SQL.",
        argument_roles=["where", "parameters"],
        extensions=_TS,
        severity="high",
    ),
    SinkRule(
        id="ts-sql-typeorm-query",
        function="DataSource.query / Repository.query",
        call_regex=r"\.\s*query\s*\(\s*`[^`]*\$\{",
        description="TypeORM raw query with template literal interpolation.",
        argument_roles=["sql", "parameters"],
        extensions=_TS,
        severity="critical",
    ),
    SinkRule(
        id="ts-sql-prisma-execute-raw-unsafe",
        function="prisma.$executeRawUnsafe",
        call_regex=r"\$\s*executeRawUnsafe\s*\(",
        description="Prisma executeRawUnsafe accepts raw SQL.",
        argument_roles=["sql"],
        extensions=_TS,
        severity="critical",
    ),
    SinkRule(
        id="ts-sql-prisma-query-raw-unsafe",
        function="prisma.$queryRawUnsafe",
        call_regex=r"\$\s*queryRawUnsafe\s*\(",
        description="Prisma queryRawUnsafe accepts raw SQL.",
        argument_roles=["sql"],
        extensions=_TS,
        severity="critical",
    ),
    SinkRule(
        id="ts-sql-mikroorm-execute",
        function="EntityManager.execute (raw)",
        call_regex=r"\.\s*execute\s*\(\s*`[^`]*\$\{",
        description="MikroORM EntityManager.execute with template literal.",
        argument_roles=["query", "params"],
        extensions=_TS,
        severity="high",
    ),
]

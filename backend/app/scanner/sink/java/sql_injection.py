"""Java — SQL Injection sinks (CWE-89)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "sql_injection"

_JAVA = [".java", ".kt", ".scala", ".groovy"]

RULES = [
    SinkRule(
        id="java-sql-statement-execute",
        function="Statement.execute / executeQuery / executeUpdate",
        call_regex=r"\.\s*(?:execute|executeQuery|executeUpdate|executeLargeUpdate|executeBatch)\s*\(",
        description="java.sql.Statement.execute* receives full SQL string.",
        argument_roles=["sql"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-sql-preparedstatement-string-concat",
        function="connection.prepareStatement(concatSql)",
        call_regex=r"\.\s*prepareStatement\s*\(",
        description="PreparedStatement is safe only when SQL is a static literal; flagged when concatenated.",
        argument_roles=["sql"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-sql-jdbc-template-query",
        function="JdbcTemplate.query / queryForObject / update",
        call_regex=r"\.\s*(?:query|queryForObject|queryForList|queryForMap|queryForRowSet|update|batchUpdate)\s*\(",
        description="Spring JdbcTemplate methods with formatted SQL string.",
        argument_roles=["sql", "args"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-sql-namedparameter-jdbc",
        function="NamedParameterJdbcTemplate.query (concatenated)",
        call_regex=r"\bNamedParameterJdbcTemplate[\s\S]{0,40}\.\s*(?:query|update)\s*\(",
        description="NamedParameter variant; still vulnerable when SQL string is concatenated.",
        argument_roles=["sql", "paramMap"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-sql-hibernate-createquery",
        function="Session.createQuery / createSQLQuery / createNativeQuery",
        call_regex=r"\.\s*create(?:Query|SQLQuery|NativeQuery)\s*\(",
        description="Hibernate query construction with concatenated HQL/SQL.",
        argument_roles=["queryString"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-sql-jpa-createnativequery",
        function="EntityManager.createNativeQuery",
        call_regex=r"\.\s*createNativeQuery\s*\(",
        description="JPA EntityManager native query with raw SQL string.",
        argument_roles=["sqlString"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-sql-mybatis-statement",
        function="MyBatis @Select / ${...} substitution",
        call_regex=r"\$\{[^}]+\}",
        description="MyBatis ${} performs raw substitution (use #{} instead).",
        argument_roles=[],
        extensions=[".java", ".xml"],
        severity="high",
    ),
    SinkRule(
        id="java-sql-jooq-fetch-raw",
        function="DSL.fetch / DSLContext.execute(raw)",
        call_regex=r"\bDSL\s*\.\s*(?:fetch|execute)\s*\(\s*\"",
        description="jOOQ DSL.fetch with raw string argument.",
        argument_roles=["sql"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-sql-spring-data-query-spel",
        function="@Query with SpEL :#{}",
        call_regex=r"@Query\s*\(\s*\"[^\"]*:#\{",
        description="Spring Data @Query with SpEL expression — review for injection.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
]

"""Java — NoSQL Injection sinks (Mongo, Redis Lua, Cassandra ALLOW FILTERING)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "nosql_injection"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-nosql-mongo-bson-eval",
        function="MongoDatabase.runCommand({eval:...})",
        call_regex=r"\.\s*runCommand\s*\(",
        description="MongoDB runCommand with eval/$where Lua script.",
        argument_roles=["command"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-nosql-mongo-where",
        function="Filters.where(jsScript)",
        call_regex=r"\bFilters\s*\.\s*where\s*\(",
        description="MongoDB $where with user-controlled JS.",
        argument_roles=["javaScriptExpression"],
        extensions=_JAVA,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-nosql-spring-mongotemplate-find",
        function="MongoTemplate.find(Query.query(Criteria.where(...)))",
        call_regex=r"\bMongoTemplate\b[\s\S]{0,80}\.\s*(?:find|findOne|findAll)\s*\(",
        description="MongoTemplate query — verify Criteria is parameterised, not concatenated.",
        argument_roles=["query"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-nosql-jedis-eval",
        function="Jedis.eval(script)",
        call_regex=r"\.\s*eval(?:sha)?\s*\(",
        description="Redis Lua EVAL with user-controlled script.",
        argument_roles=["script", "keys", "args"],
        extensions=_JAVA,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-nosql-cassandra-allowfiltering",
        function="CQL with ALLOW FILTERING and dynamic predicate",
        call_regex=r"ALLOW\s+FILTERING",
        description="ALLOW FILTERING + concatenated predicates — review CQL injection.",
        argument_roles=[],
        extensions=_JAVA,
        severity="medium",
    ),
]

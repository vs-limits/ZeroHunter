"""Python — NoSQL Injection sinks (CWE-943)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "nosql_injection"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-nosql-pymongo-find-where",
        function="pymongo Collection.find with $where",
        call_regex=r"\.\s*find(?:_one)?\s*\(",
        description="MongoDB find() carrying a $where JS string built from user input.",
        argument_roles=["filter"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"\$where", r"\$expr"],
    ),
    SinkRule(
        id="py-nosql-pymongo-aggregate",
        function="pymongo Collection.aggregate",
        call_regex=r"\.\s*aggregate\s*\(",
        description="MongoDB aggregate pipeline with $where / $function.",
        argument_roles=["pipeline"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-nosql-pymongo-eval",
        function="Database.eval",
        call_regex=r"\.\s*eval\s*\(",
        description="MongoDB server-side eval() runs JS on the server.",
        argument_roles=["code"],
        extensions=_PY,
        severity="critical",
    ),
    SinkRule(
        id="py-nosql-redis-eval",
        function="redis.Redis.eval / evalsha",
        call_regex=r"\.\s*eval(?:sha)?\s*\(",
        description="Redis EVAL with Lua source from user input.",
        argument_roles=["script", "numkeys", "keys", "args"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-nosql-elasticsearch-search",
        function="elasticsearch.search query_string",
        call_regex=r"\.\s*search\s*\(",
        description="Elasticsearch search body using query_string with user input.",
        argument_roles=["body", "params"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
        extra_match_regex=[r"query_string", r"script\s*:"],
    ),
    SinkRule(
        id="py-nosql-couchdb-view",
        function="couchdb db.view / db.query",
        call_regex=r"\.\s*(?:view|query)\s*\(",
        description="CouchDB temporary view / MapReduce with user-controlled JS.",
        argument_roles=["map_fun", "reduce_fun"],
        extensions=_PY,
        severity="high",
        require_dynamic=True,
    ),
]

"""PHP — NoSQL Injection sinks (CWE-943)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "nosql_injection"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-nosql-mongodb-find",
        function="MongoDB Collection::find / findOne",
        # Gate with a MongoDB-context hint on the line so we don't flag every
        # `->find(...)` / `->update(...)` Doctrine/ORM call in non-Mongo code.
        call_regex=r"->\s*(?:find|findOne|findAndModify|aggregate|update(?:One|Many)?|delete(?:One|Many)?|count(?:Documents)?)\s*\(",
        description="MongoDB queries that accept arrays; user-controlled keys/operators allow operator injection ($ne, $gt, ...).",
        argument_roles=["filter", "options"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"Mongo", r"\bBSON\b", r"->\s*getCollection\s*\(", r"new\s+MongoDB\\"],
    ),
    SinkRule(
        id="php-nosql-mongodb-execute",
        function="MongoDB Manager::executeQuery / executeCommand",
        call_regex=r"->\s*execute(?:Query|Command|BulkWrite)\s*\(",
        description="Low-level MongoDB Manager calls; injection if BSON document is built from user input.",
        argument_roles=["namespace_or_db", "query_or_command"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"Mongo", r"Manager", r"\bBSON\b"],
    ),
    SinkRule(
        id="php-nosql-mongodb-eval",
        function="db.eval / MongoDB\\Driver\\Command runOn server",
        call_regex=r"->\s*command\s*\(\s*\[[^]]*['\"]\s*\$eval",
        description="Calls MongoDB $eval / runCommand({eval: ...}) which executes JS server-side (SSJI).",
        argument_roles=["command"],
        extensions=_PHP,
        severity="critical",
    ),
    SinkRule(
        id="php-nosql-redis-eval",
        function="Redis::eval",
        call_regex=r"->\s*eval\s*\(\s*['\"]",
        description="Redis EVAL runs Lua server-side; injecting script can dump keys.",
        argument_roles=["script", "keys", "args"],
        extensions=_PHP,
        severity="high",
        require_dynamic=True,
    ),
]

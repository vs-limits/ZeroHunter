"""Go — NoSQL Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "nosql_injection"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-nosql-mongo-find",
        function="mongo.Collection.Find / FindOne / Aggregate",
        call_regex=r"\.\s*(?:Find|FindOne|FindOneAndUpdate|FindOneAndDelete|Aggregate|UpdateOne|UpdateMany|DeleteOne|DeleteMany)\s*\(",
        description="mongo-go-driver query using bson filter built from request body.",
        argument_roles=["ctx", "filter"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-nosql-mongo-runcommand",
        function="Database.RunCommand({eval:...})",
        call_regex=r"\.\s*RunCommand\s*\(",
        description="MongoDB RunCommand with eval / $where.",
        argument_roles=["ctx", "runCommand"],
        extensions=_GO,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-nosql-redis-eval",
        function="redis.Client.Eval / EvalSha",
        call_regex=r"\.\s*Eval(?:Sha)?\s*\(",
        description="Redis Lua EVAL with user-controlled script.",
        argument_roles=["ctx", "script", "keys", "args"],
        extensions=_GO,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-nosql-couchbase-n1ql-raw",
        function="cluster.Query(rawN1QL)",
        call_regex=r"\.\s*Query\s*\(\s*fmt\.Sprintf",
        description="Couchbase N1QL built via fmt.Sprintf.",
        argument_roles=["statement"],
        extensions=_GO,
        severity="high",
    ),
]

"""JavaScript / Node.js — NoSQL Injection sinks (CWE-943)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "nosql_injection"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-nosql-mongo-find-with-req",
        function="collection.find / findOne with req.body",
        call_regex=r"\.\s*(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(",
        description="MongoDB query directly using req.body/req.query without type sanitisation.",
        argument_roles=["filter"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
        extra_match_regex=[r"req\.body", r"req\.query", r"req\.params", r"\$where"],
    ),
    SinkRule(
        id="js-nosql-mongo-where",
        function="MongoDB $where operator",
        call_regex=r"\$where\s*:",
        description="$where in query enables server-side JS execution.",
        argument_roles=[],
        extensions=_JS,
        severity="critical",
    ),
    SinkRule(
        id="js-nosql-mongoose-aggregate",
        function="Model.aggregate(pipeline)",
        call_regex=r"\.\s*aggregate\s*\(",
        description="Mongoose aggregate pipeline built from user input.",
        argument_roles=["pipeline"],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-nosql-redis-eval",
        function="redis.eval / evalsha",
        call_regex=r"\.\s*(?:eval|evalsha)\s*\(",
        description="Redis EVAL with Lua source from user input.",
        argument_roles=["script", "numkeys", "keys", "args"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
    SinkRule(
        id="js-nosql-couchdb-temporary-view",
        function="nano db.view with map function",
        call_regex=r"\.\s*view(?:WithList)?\s*\(",
        description="CouchDB view containing user-controlled JS.",
        argument_roles=["designname", "viewname", "params"],
        extensions=_JS,
        severity="high",
        require_dynamic=True,
    ),
]

"""Python — GraphQL Injection sinks (CWE-89-like, query smuggling)."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "graphql_injection"

_PY = [".py", ".pyi", ".pyw"]

RULES = [
    SinkRule(
        id="py-graphql-graphene-execute",
        function="graphene.Schema.execute",
        call_regex=r"\.\s*execute\s*\(\s*[a-zA-Z_]",
        description="Graphene Schema.execute with raw query string from user input.",
        argument_roles=["query", "variables"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-graphql-gql-client",
        function="gql.Client.execute",
        call_regex=r"\b(?:gql|client)\.\s*execute\s*\(",
        description="gql client executing a query/mutation built via string interpolation.",
        argument_roles=["document"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-graphql-strawberry-execute",
        function="strawberry.Schema.execute_sync",
        call_regex=r"\.\s*execute(?:_sync)?\s*\(",
        description="Strawberry Schema execute with concatenated GraphQL string.",
        argument_roles=["query", "variable_values"],
        extensions=_PY,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="py-graphql-introspection",
        function="introspection enabled in prod",
        call_regex=r"introspection\s*=\s*True",
        description="GraphQL server with introspection on in non-dev environment.",
        argument_roles=[],
        extensions=_PY,
        severity="low",
    ),
    SinkRule(
        id="py-graphql-batching-no-limit",
        function="Batch query without depth/cost limit",
        call_regex=r"\bGraphQLView\s*\.\s*as_view\s*\(",
        description="GraphQLView mounted — verify depth / cost / rate limit middleware.",
        argument_roles=[],
        extensions=_PY,
        severity="low",
    ),
]

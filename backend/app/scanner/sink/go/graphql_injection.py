"""Go — GraphQL Injection / Misuse sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "graphql_injection"

_GO = [".go"]

RULES = [
    SinkRule(
        id="go-graphql-handler-introspection",
        function="handler.New(... Introspection: true)",
        call_regex=r"Introspection\s*:\s*true",
        description="GraphQL handler with introspection enabled in prod.",
        argument_roles=[],
        extensions=_GO,
        severity="low",
    ),
    SinkRule(
        id="go-graphql-do-with-fmt",
        function="graphql.Do(params) with fmt.Sprintf query",
        call_regex=r"\bgraphql\s*\.\s*Do\s*\(",
        description="graphql-go Do() — verify Query string is not built via fmt.Sprintf.",
        argument_roles=["params"],
        extensions=_GO,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="go-graphql-no-complexity",
        function="schema without complexity limit",
        call_regex=r"\bgraphql\s*\.\s*NewSchema\s*\(",
        description="Schema created — verify QueryComplexity limit.",
        argument_roles=[],
        extensions=_GO,
        severity="low",
    ),
]

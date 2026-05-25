"""Java — GraphQL Injection / Misuse sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "graphql_injection"

_JAVA = [".java", ".kt", ".scala"]

RULES = [
    SinkRule(
        id="java-graphql-execute",
        function="GraphQL.execute(query)",
        call_regex=r"\bGraphQL\b[\s\S]{0,40}\.\s*execute\s*\(",
        description="graphql-java execute with concatenated query string.",
        argument_roles=["query"],
        extensions=_JAVA,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="java-graphql-introspection-on",
        function="introspection enabled",
        call_regex=r"\.\s*introspection\s*\(\s*true\s*\)",
        description="Builder.introspection(true) leaves schema discoverable.",
        argument_roles=[],
        extensions=_JAVA,
        severity="low",
    ),
    SinkRule(
        id="java-graphql-no-depth-limit",
        function="GraphQL.Builder no MaxQueryDepth",
        call_regex=r"\bGraphQL\s*\.\s*newGraphQL\s*\(",
        description="GraphQL builder — verify MaxQueryDepth instrumentation.",
        argument_roles=[],
        extensions=_JAVA,
        severity="low",
    ),
]

"""JavaScript / Node.js — GraphQL Injection / Misuse sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "graphql_injection"

_JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

RULES = [
    SinkRule(
        id="js-graphql-apollo-introspection",
        function="ApolloServer introspection:true",
        call_regex=r"introspection\s*:\s*true",
        description="Apollo introspection enabled in production exposes schema.",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-graphql-no-depth-limit",
        function="graphql-depth-limit middleware missing",
        call_regex=r"\bnew\s+ApolloServer\s*\(",
        description="ApolloServer construction — verify depth/cost limit plugins.",
        argument_roles=[],
        extensions=_JS,
        severity="low",
    ),
    SinkRule(
        id="js-graphql-gql-template-with-user",
        function="gql`...${userInput}...`",
        call_regex=r"\bgql`[^`]*\$\{",
        description="Building GraphQL query via template literal interpolation.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
    ),
    SinkRule(
        id="js-graphql-makeexecutableschema-dynamic",
        function="makeExecutableSchema with dynamic typeDefs",
        call_regex=r"\bmakeExecutableSchema\s*\(\s*\{[^}]*typeDefs",
        description="Schema typeDefs interpolated from runtime data.",
        argument_roles=[],
        extensions=_JS,
        severity="medium",
        require_dynamic=True,
    ),
]

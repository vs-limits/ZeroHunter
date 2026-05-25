"""PHP — GraphQL Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "graphql_injection"

_PHP = [".php", ".phtml", ".inc"]

RULES = [
    SinkRule(
        id="php-graphql-execute-dynamic",
        function="GraphQL\\GraphQL::executeQuery",
        call_regex=r"GraphQL\s*::\s*executeQuery\s*\(|->\s*executeQuery\s*\(",
        description="webonyx/graphql-php executeQuery with user-controlled query string can lead to introspection abuse / batched ops abuse.",
        argument_roles=["schema", "query", "rootValue", "context", "variables"],
        extensions=_PHP,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="php-graphql-parse-dynamic",
        function="GraphQL Parser::parse",
        call_regex=r"Parser\s*::\s*parse\s*\(",
        description="Parses a raw GraphQL query string.",
        argument_roles=["source"],
        extensions=_PHP,
        severity="low",
        require_dynamic=True,
    ),
]

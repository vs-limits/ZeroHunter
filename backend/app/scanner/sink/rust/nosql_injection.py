"""Rust — NoSQL Injection sinks."""

from app.scanner.sink.types import SinkRule

VULNERABILITY = "nosql_injection"

_RS = [".rs"]

RULES = [
    SinkRule(
        id="rs-nosql-mongodb-find",
        function="mongodb::Collection.find / find_one",
        call_regex=r"\.\s*(?:find|find_one|find_one_and_update|find_one_and_delete|aggregate|update_many|delete_many)\s*\(",
        description="mongodb crate query with bson doc built from user input.",
        argument_roles=["filter", "options"],
        extensions=_RS,
        severity="medium",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-nosql-mongodb-run-command",
        function="Database.run_command(doc)",
        call_regex=r"\.\s*run_command\s*\(",
        description="MongoDB run_command with $where / eval doc.",
        argument_roles=["command", "selection_criteria"],
        extensions=_RS,
        severity="critical",
        require_dynamic=True,
    ),
    SinkRule(
        id="rs-nosql-redis-eval",
        function="redis::cmd(\"EVAL\")",
        call_regex=r"redis\s*::\s*cmd\s*\(\s*\"EVAL(?:SHA)?\"",
        description="Redis Lua EVAL with user-controlled script.",
        argument_roles=[],
        extensions=_RS,
        severity="high",
        require_dynamic=True,
    ),
]

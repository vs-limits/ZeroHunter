from enum import Enum


class AgentType(Enum):
    TREESCAN = "treescan"
    CALLSCAN = "callscan"
    SCANNER = "scanner"
    CHECKER = "checker"
    FIXER = "fixer"
    REPORTER = "reporter"

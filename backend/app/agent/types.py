from enum import Enum


class AgentRole(str, Enum):
    AUDITOR = "auditor"
    CHECKER = "checker"
    TREESCAN = "treescan"
    CALLSCAN = "callscan"
    DATAFLOWSCAN = "dataflowscan"

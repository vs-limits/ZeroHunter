"""多 Agent 底座：路由 + sub_agent 模块集合。

外部使用：
    from app.agent import run_agent, AgentRole
    profile = run_agent(AgentRole.TREESCAN, project_path)
"""
from app.agent.runner import run_agent
from app.agent.types import AgentRole

__all__ = ["run_agent", "AgentRole"]

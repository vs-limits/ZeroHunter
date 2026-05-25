from __future__ import annotations

from app.agent.module_types import AgentType
from app.agent.registry import get_agent_spec, normalize_agent_type
from app.llm.client import ask_llm


def run_agent(
    agent_role: AgentType | str,
    content: str,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> str:
    role = normalize_agent_type(agent_role)
    spec = get_agent_spec(role)

    return ask_llm(
        question=content,
        system_message=spec.system_prompt,
        temperature=temperature if temperature is not None else spec.temperature,
        max_tokens=max_tokens if max_tokens is not None else spec.max_tokens,
    )


__all__ = ["run_agent"]
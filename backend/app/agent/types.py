from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.agent.module_types import AgentType


#----------- Agent 规格：集中描述每个 Agent 的提示词、模型参数和人类可读名称 ------------#
@dataclass(frozen=True, slots=True)
class AgentSpec:
    role: AgentType
    name: str
    prompt_file: str
    system_prompt: str
    temperature: float = 0.2
    max_tokens: int = 3000


#----------- Agent 请求：调用方只描述角色、输入和可选覆盖参数 ------------#
@dataclass(frozen=True, slots=True)
class AgentRequest:
    role: AgentType
    content: str
    temperature: float | None = None
    max_tokens: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


#----------- Agent 响应：保留角色、原始文本和调用参数，方便后续写入中间产物 ------------#
@dataclass(frozen=True, slots=True)
class AgentResponse:
    role: AgentType
    content: str
    temperature: float
    max_tokens: int
    metadata: dict[str, Any] = field(default_factory=dict)

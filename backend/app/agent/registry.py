from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.agent.module_types import AgentType
from app.agent.types import AgentSpec


PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
SHARED_RULES_FILE = "_shared_output_rules.md"
COMMON_RULES_KEY = "common_rules"
PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


#----------- Agent 注册表：新增 Agent 时只需要在这里登记 prompt 文件和默认模型参数 ------------#
AGENT_CONFIGS: dict[AgentType, dict[str, Any]] = {
    AgentType.SCANNER: {
        "name": "代码扫描专家",
        "prompt": "scanner.md",
        "temperature": 0.2,
        "max_tokens": 4000,
    },
    AgentType.REPORTER: {
        "name": "漏洞报告生成专家",
        "prompt": "reporter.md",
        "temperature": 0.2,
        "max_tokens": 4000,
    },
    AgentType.TREESCAN: {
        "name": "项目画像专家",
        "prompt": "treescan.md",
        "temperature": 0.1,
        "max_tokens": 4000,
    },
    AgentType.CALLSCAN: {
        "name": "调用链分析专家",
        "prompt": "callscan.md",
        "temperature": 0.1,
        "max_tokens": 4000,
    },
    AgentType.CHECKER: {
        "name": "漏洞验证专家",
        "prompt": "checker.md",
        "temperature": 0.1,
        "max_tokens": 4000,
    },
    AgentType.FIXER: {
        "name": "漏洞修复专家",
        "prompt": "fixer.md",
        "temperature": 0.3,
        "max_tokens": 4000,
    },
}


def get_agent_spec(agent_role: AgentType | str) -> AgentSpec:
    role = normalize_agent_type(agent_role)
    try:
        config = AGENT_CONFIGS[role]
    except KeyError as exc:
        raise ValueError(f"Unknown agent type: {role}") from exc

    prompt_file = _prompt_filename(str(config["prompt"]))
    return AgentSpec(
        role=role,
        name=str(config["name"]),
        prompt_file=prompt_file,
        system_prompt=get_prompt(prompt_file),
        temperature=float(config.get("temperature", 0.2)),
        max_tokens=int(config.get("max_tokens", 3000)),
    )


def list_agent_specs() -> list[AgentSpec]:
    return [get_agent_spec(role) for role in AGENT_CONFIGS]


def normalize_agent_type(agent_role: AgentType | str) -> AgentType:
    if isinstance(agent_role, AgentType):
        return agent_role

    normalized_role = str(agent_role).strip().lower()
    for agent_type in AgentType:
        if normalized_role in (agent_type.value, agent_type.name.lower()):
            return agent_type

    allowed_roles = ", ".join(agent_type.value for agent_type in AgentType)
    raise ValueError(f"Unsupported agent role: {agent_role}. Allowed roles: {allowed_roles}")


#----------- Prompt 加载：统一处理共享规则和 {{placeholder}} 模板变量 ------------#
def get_prompt(prompt_name: str, **kwargs: Any) -> str:
    shared_rules = _read_prompt_file(SHARED_RULES_FILE)
    content = _read_prompt_file(_prompt_filename(prompt_name))
    context = {COMMON_RULES_KEY: shared_rules, **kwargs}
    return _render_template(content, context)


def _read_prompt_file(filename: str) -> str:
    path = PROMPTS_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Prompt file does not exist: {path}")

    return path.read_text(encoding="utf-8").strip()


def _prompt_filename(prompt_name: str) -> str:
    return prompt_name if prompt_name.endswith(".md") else f"{prompt_name}.md"


def _render_template(content: str, context: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        return str(context.get(key, match.group(0)))

    return PLACEHOLDER_PATTERN.sub(replace, content).strip()

"""提示词加载工具。

每个 sub_agent 在自己的文件内调用 load_prompt("auditor.md") 读取
对应的系统提示词，同时自定义自己的温度、max_tokens 等 LLM 参数。

"""

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts"
_SHARED_PLACEHOLDER = "{{SHARED_OUTPUT_RULES}}"


def _read(name: str) -> str:
    """读取 backend/prompts/<name> 的纯文本内容。"""
    path = _PROMPTS_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"提示词文件不存在: {path}")
    return path.read_text(encoding="utf-8").strip()


def load_prompt(filename: str) -> str:
    """加载某个 agent 提示词，并把共享输出规则注入到占位符位置。

    参数:
        filename: prompts/ 目录下的文件名，例如 "treescan.md"。
    """
    shared = _read("_shared_output_rules.md")
    body = _read(filename)
    if _SHARED_PLACEHOLDER not in body:
        return body
    return body.replace(_SHARED_PLACEHOLDER, shared)

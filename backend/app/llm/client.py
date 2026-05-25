from typing import Dict, List, Optional


SYSTEM_MESSAGE = (
    "你是 DefectMine 的智能助手，专注于根据输入的源代码分析代码缺陷，"
    "输出潜在漏洞以及验证方式。"
)

EMPTY_RESPONSE_MESSAGE = "LLM 未返回有效内容，请检查模型响应、请求参数或服务状态。"

def ask_llm(
    question: str,
    system_message: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: int = 1500,
) -> str:
    messages = [
        {"role": "system", "content": system_message or SYSTEM_MESSAGE},
        {"role": "user", "content": question},
    ]
    return chat_completion(
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def chat_completion(
    messages: List[Dict[str, str]],
    temperature: float = 0.7,
    max_tokens: int = 1500,
) -> str:
    from litellm import completion

    from app.core.config import LLM_APIKEY, LLM_BASEURL, LLM_MODEL, LLM_PROVIDER

    response = completion(
        model=f"{LLM_PROVIDER}/{LLM_MODEL}",
        api_key=LLM_APIKEY,
        api_base=LLM_BASEURL.rstrip("/"),
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return _message_content(response)


def _message_content(response) -> str:
    choice = response.choices[0]
    message = choice.message

    if isinstance(message, dict):
        content = message.get("content")
    else:
        content = getattr(message, "content", None)

    if not content:
        return EMPTY_RESPONSE_MESSAGE

    return content

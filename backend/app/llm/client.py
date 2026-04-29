import re

from litellm import completion

from app.core.config import LLM_APIKEY, LLM_BASEURL, LLM_MODEL, LLM_PROVIDER


SYSTEM_MESSAGE = (
    "你是 DefectMine 的智能助手，专注于根据输入的源代码分析代码缺陷，"
    "输出潜在漏洞以及验证方式。"
)

DEFAULT_USER_MESSAGE = """请分析以下代码，输出潜在的漏洞以及验证方式：

```python
def vulnerable_function(user_input):
    eval(user_input)
```
"""

def ask_llm(question: str) -> str:
    response = completion(
        model=f"{LLM_PROVIDER}/{LLM_MODEL}",
        api_key=LLM_APIKEY,
        api_base=LLM_BASEURL.rstrip("/"),
        messages=[
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": question},
        ],
        temperature=0.7,
        max_tokens=1500,
    )
    return _message_content(response)


if __name__ == "__main__":
    print(ask_llm(DEFAULT_USER_MESSAGE))

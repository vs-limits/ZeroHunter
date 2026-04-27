from pathlib import Path

ENV_PATH = Path(__file__).parent / "config" / ".env"

LLM_BASEURL = None
LLM_APIKEY = None
LLM_MODEL = None
LLM_PROVIDER = None

with open(ENV_PATH, "r", encoding="utf-8") as f:
    if not f:
        raise ValueError(f"未找到配置文件: {ENV_PATH}，请复制 .env.example 并重命名为 .env")
    for line in f:
        if line.startswith("LLM_BASEURL"):
            LLM_BASEURL = line.split("=",1)[1].strip().strip('"').strip("'")
        elif line.startswith("LLM_APIKEY"):
            LLM_APIKEY = line.split("=",1)[1].strip().strip('"').strip("'")
        elif line.startswith("LLM_MODEL"):
            LLM_MODEL = line.split("=",1)[1].strip().strip('"').strip("'")
        elif line.startswith("LLM_PROVIDER"):
            LLM_PROVIDER = line.split("=",1)[1].strip().strip('"').strip("'")
    """
    LLM_BASEURL = "<配置地址>"
    LLM_APIKEY = "<API密钥>"
    LLM_MODEL = "<模型名称>"
    LLM_PROVIDER = "<LLM提供商名称>"
    """


if not all([LLM_BASEURL, LLM_APIKEY, LLM_MODEL, LLM_PROVIDER]):
    raise ValueError(f"请确保 .env 文件中包含以下配置项: LLM_BASEURL, LLM_APIKEY, LLM_MODEL, LLM_PROVIDER")




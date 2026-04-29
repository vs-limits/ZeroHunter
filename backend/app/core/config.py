from pathlib import Path
import os
from dotenv import load_dotenv 

ENV_PATH = Path(__file__).parent.parent / "config" / ".env"

LLM_BASEURL = None
LLM_APIKEY = None
LLM_MODEL = None
LLM_PROVIDER = None

if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)
    LLM_BASEURL = os.getenv("LLM_BASEURL")
    LLM_APIKEY = os.getenv("LLM_APIKEY")
    LLM_MODEL = os.getenv("LLM_MODEL")
    LLM_PROVIDER = os.getenv("LLM_PROVIDER")
    """
    LLM_BASEURL = "<配置地址>"
    LLM_APIKEY = "<API密钥>"
    LLM_MODEL = "<模型名称>"
    LLM_PROVIDER = "<LLM提供商名称>"
    """
else:
    raise FileNotFoundError(f"未找到 .env 文件，请确保在 {ENV_PATH} 路径下存在 .env 文件，并包含必要的配置项")
if not all([LLM_BASEURL, LLM_APIKEY, LLM_MODEL, LLM_PROVIDER]):
    raise ValueError(f"请确保 .env 文件中包含以下配置项: LLM_BASEURL, LLM_APIKEY, LLM_MODEL, LLM_PROVIDER")
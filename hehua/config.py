from __future__ import annotations
import os
from dataclasses import dataclass

def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, '') or default)
    except ValueError:
        return default

@dataclass
class Config:
    deepseek_api_key: str = ''
    deepseek_base_url: str = 'https://api.deepseek.com/v1'
    deepseek_model: str = 'deepseek-chat'
    deepseek_pro_model: str = 'deepseek-v4-pro'
    aliyun_api_key: str = ''
    aliyun_base_url: str = 'https://dashscope.aliyuncs.com/compatible-mode/v1'
    qwen_model: str = 'qwen3-max'
    # '' = compact with the main model (some endpoints have no cheap tier)
    qwen_compact_model: str = ''
    glm_api_key: str = ''
    glm_model: str = 'glm-5.3'
    kimi_api_key: str = ''
    kimi_model: str = 'kimi-k3'
    llm_provider: str = 'deepseek'
    peers: int = 2
    thinking: str = 'on'
    head_tail: int = 4096
    bash_timeout_max: int = 1200
    ctx_compact_ratio: float = 0.75
    ctx_limit: int = 60000
    token_soft_limit: int = 150000000

def _load_dotenv(path: str='.env') -> None:
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                os.environ.setdefault(k.strip(), v.strip().strip('"'))
    except OSError:
        pass
_load_dotenv()

def load_config() -> Config:
    return Config(deepseek_api_key=os.getenv('DEEPSEEK_API_KEY', ''), deepseek_base_url=os.getenv('DEEPSEEK_BASE_URL', 'https://api.deepseek.com/v1'), deepseek_model=os.getenv('DEEPSEEK_MODEL', 'deepseek-chat'), deepseek_pro_model=os.getenv('DEEPSEEK_PRO_MODEL', 'deepseek-v4-pro'), aliyun_api_key=os.getenv('ALIYUN_API_KEY', ''), aliyun_base_url=os.getenv('ALIYUN_BASE_URL', 'https://dashscope.aliyuncs.com/compatible-mode/v1'), qwen_model=os.getenv('QWEN_MODEL', 'qwen3-max'), qwen_compact_model=os.getenv('QWEN_COMPACT_MODEL', ''), glm_api_key=os.getenv('GLM_API_KEY', ''), glm_model=os.getenv('GLM_MODEL', 'glm-5.3'), kimi_api_key=os.getenv('KIMI_API_KEY', ''), kimi_model=os.getenv('KIMI_MODEL', 'kimi-k3'), llm_provider=os.getenv('LLM_PROVIDER', 'deepseek'), thinking=os.getenv('HEHUA_THINKING', 'on'), peers=_int('HEHUA_PEERS', 2), head_tail=_int('HEHUA_HEAD_TAIL', 4096), bash_timeout_max=_int('HEHUA_BASH_TIMEOUT_MAX', 1200), ctx_limit=_int('HEHUA_CTX_LIMIT', 60000), token_soft_limit=_int('HEHUA_TOKEN_SOFT_LIMIT', 150000000))

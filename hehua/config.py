from __future__ import annotations
import os
from dataclasses import dataclass, field

def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, '') or default)
    except ValueError:
        return default

@dataclass
class Config:
    benchmark_token: str = ''
    benchmark_base_url: str = ''
    deepseek_api_key: str = ''
    deepseek_base_url: str = 'https://api.deepseek.com/v1'
    deepseek_model: str = 'deepseek-chat'
    aliyun_api_key: str = ''
    aliyun_base_url: str = 'https://dashscope.aliyuncs.com/compatible-mode/v1'
    qwen_model: str = 'qwen3-max'
    qwen_compact_model: str = 'qwen-turbo'
    glm_api_key: str = ''
    glm_model: str = 'glm-5.2'
    kimi_api_key: str = ''
    kimi_model: str = 'kimi-k3'
    llm_provider: str = 'deepseek'
    pool: int = 3
    deep_mode: str = 'auto'
    peers: int = 2
    max_challenge_attempts: int = 3
    model_gateway: bool = False
    mock_llm: bool = False
    thinking: str = 'on'
    total_budget_min: int = 360
    reserve_min: int = 45
    level_budget_min: dict = field(default_factory=lambda: {'easy': 4, 'medium': 8, 'hard': 15, 'default': 8})
    max_steps: int = 150
    tool_result_max: int = 8192
    head_tail: int = 4096
    bash_timeout: int = 120
    bash_timeout_max: int = 300
    ctx_compact_ratio: float = 0.75
    ctx_limit: int = 60000
    token_soft_limit: int = 150000000
    repeat_cmd_threshold: int = 3
    no_progress_steps: int = 8

    @property
    def net_budget_min(self) -> int:
        return self.total_budget_min - self.reserve_min

    @property
    def mode(self) -> str:
        m = os.getenv('HEHUA_MODE', '')
        if m:
            return m
        if self.model_gateway:
            return 'hosted'
        return 'local'

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
    return Config(benchmark_token=os.getenv('BENCHMARK_TOKEN', ''), benchmark_base_url=os.getenv('BENCHMARK_BASE_URL', ''), deepseek_api_key=os.getenv('DEEPSEEK_API_KEY', ''), deepseek_base_url=os.getenv('DEEPSEEK_BASE_URL', 'https://api.deepseek.com/v1'), deepseek_model=os.getenv('DEEPSEEK_MODEL', 'deepseek-chat'), aliyun_api_key=os.getenv('ALIYUN_API_KEY', ''), aliyun_base_url=os.getenv('ALIYUN_BASE_URL', 'https://dashscope.aliyuncs.com/compatible-mode/v1'), qwen_model=os.getenv('QWEN_MODEL', 'qwen3-max'), qwen_compact_model=os.getenv('QWEN_COMPACT_MODEL', 'qwen-turbo'), glm_api_key=os.getenv('GLM_API_KEY', ''), glm_model=os.getenv('GLM_MODEL', 'glm-5.2'), kimi_api_key=os.getenv('KIMI_API_KEY', ''), kimi_model=os.getenv('KIMI_MODEL', 'kimi-k3'), llm_provider=os.getenv('LLM_PROVIDER', 'deepseek'), model_gateway=os.getenv('MODEL_GATEWAY', '0') == '1', mock_llm=os.getenv('MOCK_LLM', '0') == '1', thinking=os.getenv('HEHUA_THINKING', 'on'), total_budget_min=_int('TOTAL_BUDGET_MIN', 360), pool=_int('HEHUA_POOL', 3), deep_mode=os.getenv('HEHUA_DEEP', 'auto'), peers=_int('HEHUA_PEERS', 2), max_challenge_attempts=_int('HEHUA_MAX_ATTEMPTS', 3))

from __future__ import annotations
from dataclasses import dataclass
from ..config import Config

@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    api_key: str
    model: str
    compact_model: str | None = None

    @property
    def usable(self) -> bool:
        return bool(self.api_key)

def providers_from_config(cfg: Config) -> list[Provider]:
    all_providers = {'deepseek': Provider('deepseek', cfg.deepseek_base_url, cfg.deepseek_api_key, cfg.deepseek_model), 'qwen': Provider('qwen', cfg.aliyun_base_url, cfg.aliyun_api_key, cfg.qwen_model, cfg.qwen_compact_model), 'glm': Provider('glm', 'https://open.bigmodel.cn/api/paas/v4', cfg.glm_api_key, cfg.glm_model), 'kimi': Provider('kimi', 'https://api.kimi.com/v1', cfg.kimi_api_key, cfg.kimi_model)}
    chain = []
    primary = all_providers.get(cfg.llm_provider)
    if primary and primary.usable:
        chain.append(primary)
    for name, p in all_providers.items():
        if p.usable and p not in chain:
            chain.append(p)
    return chain

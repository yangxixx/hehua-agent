"""Model/provider registry — OpenAI-compatible endpoints only (all whitelisted).

Public-leaderboard intel (2026-08): kimi-k3 tops accuracy (90%/85% on open
evals) but is token-heavy (70-90M); glm-5.2 strong+efficient (~20M);
deepseek-v4-pro most token-efficient at ~7.8M for 71.6% (Excalibur) and powers
the #1 hosted run (ez-claude, 66.13). Default primary=deepseek fits the 360min
budget; switch via LLM_PROVIDER when better keys are available.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..config import Config


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str          # client appends /chat/completions
    api_key: str
    model: str             # primary model id
    compact_model: str | None = None

    @property
    def usable(self) -> bool:
        return bool(self.api_key)


def providers_from_config(cfg: Config) -> list[Provider]:
    all_providers = {
        "deepseek": Provider("deepseek", cfg.deepseek_base_url, cfg.deepseek_api_key,
                             cfg.deepseek_model),
        "qwen": Provider("qwen", cfg.aliyun_base_url, cfg.aliyun_api_key,
                         cfg.qwen_model, cfg.qwen_compact_model),
        "glm": Provider("glm", "https://open.bigmodel.cn/api/paas/v4",
                        cfg.glm_api_key, cfg.glm_model),
        "kimi": Provider("kimi", "https://api.kimi.com/v1", cfg.kimi_api_key,
                         cfg.kimi_model),
    }
    chain = []
    primary = all_providers.get(cfg.llm_provider)
    if primary and primary.usable:
        chain.append(primary)
    for name, p in all_providers.items():  # failover: any other usable provider
        if p.usable and p not in chain:
            chain.append(p)
    return chain

"""Tsecbench hosted-sandbox LLM gateway URL rewriting.

The hosted sandbox has NO public internet. LLM APIs must go through the
platform gateway:
  1. hostname gets a ".tsecbench.gw" suffix
  2. scheme https -> http
Only the 18 whitelisted provider domains are reachable.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

GATEWAY_SUFFIX = ".tsecbench.gw"

# Host-level whitelist (from Tsecbench hosted-mode docs, 18 entries).
WHITELIST_EXACT = {
    "api.hunyuan.cloud.tencent.com",
    "api.lkeap.cloud.tencent.com",
    "tokenhub.tencentmaas.com",
    "api.deepseek.com",
    "dashscope.aliyuncs.com",
    "qianfan.baidubce.com",
    "ark.cn-beijing.volces.com",
    "open.bigmodel.cn",
    "api.moonshot.cn",
    "api.siliconflow.cn",
    "spark-api-open.xf-yun.com",
    "api.minimaxi.com",
    "api.stepfun.com",
    "api.lingyiwanwu.com",
    "api.baichuan-ai.com",
    "api.xiaomimimo.com",
    "api.kimi.com",
}
# "*.maas.aliyuncs.com/compatible-mode/*" — wildcard subdomain entry.
WILDCARD_SUFFIXES = (".maas.aliyuncs.com",)


def is_whitelisted(hostname: str) -> bool:
    if not hostname:
        return False
    if hostname in WHITELIST_EXACT:
        return True
    return any(hostname.endswith(s) for s in WILDCARD_SUFFIXES)


def rewrite_for_gateway(base_url: str) -> str:
    """https://api.deepseek.com/v1 -> http://api.deepseek.com.tsecbench.gw/v1"""
    u = urlparse(base_url)
    host = u.hostname or ""
    if host.endswith(GATEWAY_SUFFIX):
        stripped = host[: -len(GATEWAY_SUFFIX)]
        if is_whitelisted(stripped):
            return base_url  # already rewritten
        raise ValueError(f"domain not in Tsecbench LLM whitelist: {stripped}")
    if not is_whitelisted(host):
        raise ValueError(f"domain not in Tsecbench LLM whitelist: {host}")
    return urlunparse(("http", host + GATEWAY_SUFFIX, u.path or "", "", "", ""))

"""Pentest-only CLI (agent code only — no benchmark/test harness).

  python -m hehua                     # interactive REPL (default): '渗透 <target>'
  python -m hehua pentest <target>    # one-shot pentest (URL / host[:port] / CIDR)
"""
from __future__ import annotations
import argparse
import os
import sys

from .config import load_config
from .llm.budget import Budget
from .llm.client import LLMClient
from .llm.registry import providers_from_config


def _pentest_llms(cfg):
    """(flash LLMClient, glm escalation|None, multi-model lineup [(llm, name)]).

    Lineup = flash + pro (shares the deepseek key) + glm + qwen (whichever keys
    are present). Single-model callers get `llm`; deep mode spawns one coding
    agent per lineup entry."""
    llm = LLMClient(providers_from_config(cfg), Budget(cfg.token_soft_limit))
    llm_glm = None
    lineup = [(llm, 'flash')]
    if cfg.deepseek_api_key and cfg.deepseek_pro_model:
        from .llm.registry import Provider
        pro = Provider('deepseek-pro', cfg.deepseek_base_url,
                       cfg.deepseek_api_key, cfg.deepseek_pro_model,
                       cfg.deepseek_model)
        lineup.append((LLMClient([pro], Budget(cfg.token_soft_limit)), 'pro'))
    if cfg.glm_api_key:
        from .llm.anthropic_client import AnthropicGLMClient
        llm_glm = AnthropicGLMClient(cfg.glm_api_key, model=cfg.glm_model,
                                     budget=llm.budget)
        lineup.append((llm_glm, 'glm'))
    if cfg.aliyun_api_key and cfg.qwen_model:
        from .llm.registry import Provider
        qwen = Provider('qwen', cfg.aliyun_base_url, cfg.aliyun_api_key,
                        cfg.qwen_model, cfg.qwen_compact_model)
        lineup.append((LLMClient([qwen], Budget(cfg.token_soft_limit)), 'qwen'))
    # arbitrary extra models — any OpenAI-compatible endpoint (domestic or not):
    # HEHUA_MODELS="kimi|https://api.moonshot.cn/v1|sk-xx|kimi-k3,hunyuan|https://api.hunyuan.cloud.tencent.com/v1|key|hunyuan-turbo"
    for spec in (os.getenv('HEHUA_MODELS', '').split(',') if os.getenv('HEHUA_MODELS') else []):
        spec = spec.strip()
        if not spec:
            continue
        parts = [x.strip() for x in spec.split('|')]
        if len(parts) < 4 or not all(parts[:4]):
            print(f'[hehua] skip malformed HEHUA_MODELS entry: {spec[:60]}')
            continue
        name, base, key, model_id = parts[0], parts[1], parts[2], parts[3]
        prov = Provider(name, base, key, model_id)
        lineup.append((LLMClient([prov], Budget(cfg.token_soft_limit)), name))
    return llm, llm_glm, lineup


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog='hehua',
        description='Autonomous pentest agent. No subcommand -> interactive REPL.')
    sub = p.add_subparsers(dest='cmd')
    sp = sub.add_parser('pentest', help='One-shot pentest of a target')
    sp.add_argument('target', help='URL | host[:port] | CIDR (e.g. 10.0.0.0/24)')
    sp.add_argument('--budget', type=float, default=30.0, help='minutes per target')
    sp.add_argument('--deep', action='store_true', help='multi-peer deep mode')
    sp.add_argument('--instruction', default='', help='extra directive')
    args = p.parse_args(argv)

    cfg = load_config()
    llm, llm_glm, lineup = _pentest_llms(cfg)
    peers = cfg.peers

    if args.cmd == 'pentest':
        from .pentest import pentest_target, pentest_range, is_cidr
        t = args.target
        if is_cidr(t):
            pentest_range(t, cfg, llm, 'out', budget_per=args.budget,
                          instruction=args.instruction, llm_glm=llm_glm,
                          deep=args.deep, peers=peers, models=lineup)
        else:
            pentest_target(t, cfg, llm, 'out', budget=args.budget,
                           instruction=args.instruction, llm_glm=llm_glm,
                           deep=args.deep, peers=peers, models=lineup)
        return 0

    from .operator import operator_repl
    budget = float(os.getenv('HEHUA_PENTEST_BUDGET', '30'))
    operator_repl(cfg, llm, llm_glm=llm_glm, workroot='out', budget=budget,
                  deep=os.getenv('HEHUA_DEEP', '') in ('deep', '1', 'on', 'yes'),
                  peers=peers, models=lineup)
    return 0


if __name__ == '__main__':
    sys.exit(main())

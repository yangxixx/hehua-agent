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
    llm = LLMClient(providers_from_config(cfg), Budget(cfg.token_soft_limit),
                    gateway=cfg.model_gateway)
    llm_glm = None
    if cfg.glm_api_key and not (cfg.mock_llm or cfg.model_gateway):
        from .llm.anthropic_client import AnthropicGLMClient
        llm_glm = AnthropicGLMClient(cfg.glm_api_key, model=cfg.glm_model,
                                     budget=llm.budget)
    return llm, llm_glm


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
    llm, llm_glm = _pentest_llms(cfg)
    peers = cfg.peers

    if args.cmd == 'pentest':
        from .pentest import pentest_target, pentest_range, is_cidr
        t = args.target
        if is_cidr(t):
            pentest_range(t, cfg, llm, 'out', budget_per=args.budget,
                          instruction=args.instruction, llm_glm=llm_glm,
                          deep=args.deep, peers=peers)
        else:
            pentest_target(t, cfg, llm, 'out', budget=args.budget,
                           instruction=args.instruction, llm_glm=llm_glm,
                           deep=args.deep, peers=peers)
        return 0

    from .operator import operator_repl
    budget = float(os.getenv('HEHUA_PENTEST_BUDGET', '30'))
    operator_repl(cfg, llm, llm_glm=llm_glm, workroot='out', budget=budget,
                  deep=os.getenv('HEHUA_DEEP', '') in ('deep', '1', 'on', 'yes'),
                  peers=peers)
    return 0


if __name__ == '__main__':
    sys.exit(main())

from __future__ import annotations
import argparse
import os
import shutil
import sys
from pathlib import Path
from .config import load_config
from .llm.budget import Budget
from .llm.client import LLMClient
from .llm.registry import providers_from_config
from .metrics.logger import EventLogger
try:
    from .orchestrate.state import State
except ImportError:
    State = None

def _build(cfg, mode: str):
    if mode == 'mock':
        from mock.mock_llm import MockLLM
        from mock.mock_platform import MockPlatform
        llm = MockLLM() if cfg.mock_llm or not cfg.deepseek_api_key else None
        platform = MockPlatform()
        if llm is None:
            llm = LLMClient(providers_from_config(cfg), Budget(cfg.token_soft_limit), gateway=cfg.model_gateway)
        return (platform, llm)
    from tsec_benchmark import TSecBenchmark
    platform = TSecBenchmark(base_url=cfg.benchmark_base_url, token=cfg.benchmark_token)
    llm = LLMClient(providers_from_config(cfg), Budget(cfg.token_soft_limit), gateway=cfg.model_gateway)
    return (platform, llm)

def _pentest_llms(cfg):
    llm = LLMClient(providers_from_config(cfg), Budget(cfg.token_soft_limit), gateway=cfg.model_gateway)
    llm_glm = None
    if cfg.glm_api_key and (not (cfg.mock_llm or cfg.model_gateway)):
        from .llm.anthropic_client import AnthropicGLMClient
        llm_glm = AnthropicGLMClient(cfg.glm_api_key, model=cfg.glm_model, budget=llm.budget)
    return (llm, llm_glm)

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog='hehua', description='Autonomous pentest agent. No subcommand -> interactive REPL.')
    sub = p.add_subparsers(dest='cmd')
    for name in ('run', 'smoke', 'resume'):
        sp = sub.add_parser(name)
        sp.add_argument('--mode', choices=['local', 'hosted', 'mock'])
    sp = sub.add_parser('pentest', help='One-shot pentest of a target')
    sp.add_argument('target', help='URL | host[:port] | CIDR (e.g. 10.0.0.0/24)')
    sp.add_argument('--budget', type=float, default=30.0, help='minutes per target')
    sp.add_argument('--deep', action='store_true', help='multi-peer deep mode')
    sp.add_argument('--instruction', default='', help='extra directive')
    sp.add_argument('--mode', choices=['local', 'hosted', 'mock'])
    sub.add_parser('report')
    args = p.parse_args(argv)
    if args.cmd == 'report':
        if State is None:
            print('report requires the benchmark build (orchestrate/).')
            return 1
        from .metrics.report import generate
        print(generate(State.load(), Budget().totals(), 'logs/events.jsonl'))
        return 0
    mode = getattr(args, 'mode', None) or os.getenv('HEHUA_MODE', 'local')
    os.environ['HEHUA_MODE'] = mode
    cfg = load_config()
    if args.cmd == 'smoke':
        if State is None:
            print('smoke requires the benchmark build (orchestrate/ + mock/).')
            return 1
        mode = 'mock'
        os.environ['HEHUA_MODE'] = 'mock'
        os.environ['MOCK_LLM'] = '1'
        cfg = load_config()
        for d in ('state_smoke', 'logs_smoke', 'out_smoke'):
            shutil.rmtree(d, ignore_errors=True)
        events = EventLogger('logs_smoke/events.jsonl')
        state = State.load('state_smoke/state.json')
        platform, llm = _build(cfg, 'mock')
        report = _run_with(cfg, platform, llm, events, state, 'out_smoke')
        unsolved = sorted((c for c, s in state.challenges.items() if s.status != 'solved'))
        if unsolved:
            print(f'SMOKE FAIL: unsolved mock challenges {unsolved} (report: {report})')
            return 1
        print(f'SMOKE OK -> {report}')
        return 0
    if args.cmd in ('run', 'resume'):
        if State is None:
            print('run/resume requires the benchmark build (orchestrate/ + mock/).')
            return 1
        if mode == 'mock' and (not cfg.benchmark_token):
            os.environ.setdefault('MOCK_LLM', '1')
            cfg = load_config()
        events = EventLogger()
        state = State.load()
        platform, llm = _build(cfg, mode)
        report = _run_with(cfg, platform, llm, events, state, 'out')
        print(f'RUN DONE -> {report}')
        return 0
    from .pentest import pentest_target, pentest_range, repl, is_cidr
    llm, llm_glm = _pentest_llms(cfg)
    deep = args.cmd == 'pentest' and args.deep
    peers = cfg.peers
    if args.cmd == 'pentest':
        t = args.target
        if is_cidr(t):
            pentest_range(t, cfg, llm, 'out', budget_per=args.budget, instruction=args.instruction, llm_glm=llm_glm, deep=deep, peers=peers)
        else:
            pentest_target(t, cfg, llm, 'out', budget=args.budget, instruction=args.instruction, llm_glm=llm_glm, deep=deep, peers=peers)
        return 0
    from .operator import operator_repl
    budget = float(os.getenv('HEHUA_PENTEST_BUDGET', '30'))
    operator_repl(cfg, llm, llm_glm=llm_glm, workroot='out', budget=budget, deep=os.getenv('HEHUA_DEEP', '') in ('deep', '1', 'on', 'yes'), peers=peers)
    return 0

def _run_with(cfg, platform, llm, events, state, workdir):
    try:
        from .orchestrate.runner import run
        return run(cfg, platform, llm, events, state, workdir_root=workdir)
    finally:
        if hasattr(platform, 'shutdown'):
            platform.shutdown()
if __name__ == '__main__':
    sys.exit(main())

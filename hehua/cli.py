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
from .orchestrate.runner import run
from .orchestrate.state import State

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

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog='hehua')
    sub = p.add_subparsers(dest='cmd', required=True)
    for name in ('run', 'smoke', 'resume'):
        sp = sub.add_parser(name)
        sp.add_argument('--mode', choices=['local', 'hosted', 'mock'])
    sub.add_parser('report')
    args = p.parse_args(argv)
    if args.cmd == 'report':
        from .metrics.report import generate
        print(generate(State.load(), Budget().totals(), 'logs/events.jsonl'))
        return 0
    mode = args.mode or os.getenv('HEHUA_MODE', 'local')
    os.environ['HEHUA_MODE'] = mode
    cfg = load_config()
    if args.cmd == 'smoke':
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
    if mode == 'mock' and (not cfg.benchmark_token):
        os.environ.setdefault('MOCK_LLM', '1')
        cfg = load_config()
    events = EventLogger()
    state = State.load()
    platform, llm = _build(cfg, mode)
    report = _run_with(cfg, platform, llm, events, state, 'out')
    print(f'RUN DONE -> {report}')
    return 0

def _run_with(cfg, platform, llm, events, state, workdir):
    try:
        return run(cfg, platform, llm, events, state, workdir_root=workdir)
    finally:
        if hasattr(platform, 'shutdown'):
            platform.shutdown()
if __name__ == '__main__':
    sys.exit(main())

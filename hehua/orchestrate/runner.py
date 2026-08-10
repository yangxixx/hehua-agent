from __future__ import annotations
import os
import queue
import threading
import time
from dataclasses import asdict
from pathlib import Path
from tsec_benchmark import InvalidState
from ..core import agent as agentmod
from ..core.knowledge import Knowledge
from ..core.memory import Notes
from ..metrics.report import generate
from . import scheduler
from .lifecycle import Lifecycle
from .state import FAILED, PARTIAL, SKIPPED, SOLVED, State
PEER_DIRECTIONS = ['recon + known-product CVE: fingerprint product/version, nuclei sweep, adapt a public PoC', 'auth & logic: register 2 accounts, IDOR / privilege escalation / JWT-session tamper', 'injection & path abuse: SQLi, command injection, LFI/RFI/SSTI/SSRF, file upload', 'exposure & config: backups, .git, env/debug endpoints, default creds, metadata']

def _build_esc_llm(cfg, budget):
    if not cfg.glm_api_key:
        return None
    from ..llm.anthropic_client import AnthropicGLMClient
    return AnthropicGLMClient(cfg.glm_api_key, model=cfg.glm_model, budget=budget)

def run(cfg, platform_client, llm, events, state: State, workdir_root: str='out') -> str:
    life = Lifecycle(platform_client, events)
    life.cleanup_orphans(state)
    challenges = [c for c in life.list_challenges() if not c.is_completed]
    events.log('run_start', n_challenges=len(challenges), mode=cfg.mode, deep=cfg.deep_mode, pool=cfg.pool, peers=cfg.peers)
    deadline = time.time() + cfg.net_budget_min * 60
    workroot = Path(workdir_root)
    kb = Knowledge(workroot / 'knowledge.jsonl')
    if not kb.entries:
        seed = Path(os.getenv('HEHUA_KB_SEED', '/app/learned/knowledge.jsonl'))
        nseed = kb.seed_from(seed)
        if nseed:
            events.log('kb_seeded', n=nseed, src=str(seed))
    flag_counts: dict[str, int] = {}
    llm_glm = None if cfg.mock_llm or cfg.model_gateway else _build_esc_llm(cfg, llm.budget)
    glm_disabled = threading.Event()
    if llm_glm is not None:
        events.log('escalation_enabled', model=cfg.glm_model)
    mode = 'normal' if cfg.mock_llm else cfg.deep_mode
    max_attempts = cfg.max_challenge_attempts
    ordered = scheduler.order(challenges)
    fresh_q: queue.Queue = queue.Queue()
    retry_q: queue.Queue = queue.Queue()
    for c in ordered:
        if state.get(c.unique_code).attempts == 0:
            fresh_q.put(c)
        elif state.get(c.unique_code).status in (FAILED, PARTIAL):
            retry_q.put(c)
    in_flight_lock = threading.Lock()
    in_flight = 0
    stop = threading.Event()

    def peers_for(use_glm: bool) -> int:
        if cfg.mock_llm or mode == 'normal':
            return 1
        if mode == 'deep':
            return cfg.peers
        return cfg.peers if use_glm else 1

    def adaptive_budget(base: float) -> float:
        remaining_min = max(0.0, (deadline - time.time()) / 60)
        n_elig = max(1, sum((1 for c in challenges if state.get(c.unique_code).status != SOLVED and state.get(c.unique_code).attempts < max_attempts)))
        tpr = remaining_min * max(1, cfg.pool) / n_elig
        if tpr > base:
            return min(base * 1.6, tpr, remaining_min)
        return min(base, remaining_min)

    def run_challenge(ch, n_peers: int, use_glm: bool) -> None:
        code = ch.unique_code
        cs = state.get(code)
        cs.flag_count = ch.flag_count
        cs.difficulty = getattr(ch, 'difficulty', 'unknown') or 'unknown'
        try:
            started = life.start(ch, scheduler.priority)
        except Exception as e:
            events.log('start_error', code=code, error=str(e)[:200])
            cs.status = FAILED
            state.save()
            return
        if started is None:
            cs.status = SKIPPED
            state.save()
            return
        cs.attempts += 1
        cs.status = 'running'
        state.save()
        addrs = list(started.container_addr)
        wd = workroot / code
        wd.mkdir(parents=True, exist_ok=True)
        notes = Notes(wd / 'notes.jsonl')
        stop_event = threading.Event()
        chd = asdict(ch) if hasattr(ch, '__dataclass_fields__') else dict(ch)
        attempt_n = cs.attempts
        had_progress = cs.facts > 0

        def submit_logged(flag, writeup=''):
            r = life.submit(ch, flag, writeup)
            events.log('submit', code=code, flag=flag, correct=r['correct'], remaining=r['remaining'])
            if r['correct']:
                flag_counts[code] = max(flag_counts.get(code, 0), max(0, ch.flag_count - r['remaining']))
                if n_peers > 1:
                    stop_event.set()
            return r
        glm_ok = llm_glm is not None and (not glm_disabled.is_set())
        dead_ends = [e['content'] for e in notes.entries if e.get('kind') == 'failure'][:8]
        hint = None
        if attempt_n > 1 and had_progress and (not cfg.mock_llm):
            hint = life.hint(ch)
        intel = cs.intel or None
        diff = (getattr(ch, 'difficulty', '') or '').lower()
        base = {'easy': 8.0, 'medium': 14.0, 'hard': 22.0}.get(diff, 14.0) if use_glm else scheduler.budget_for(ch, cfg)
        if attempt_n > 1 and had_progress:
            budget = min(6.0, max(2.0, (deadline - time.time()) / 60))
        else:
            budget = adaptive_budget(base)
        n_peers = 1 if cfg.mock_llm else max(1, n_peers)
        if n_peers > 1 and (not cfg.mock_llm):
            rb = min(3.0, budget)
            events.log('challenge_start', code=code, phase='recon', peers=1, budget_min=round(rb, 1))
            try:
                agentmod.solve_challenge(chd, addrs, cfg, llm, notes, submit_logged, events, wd, budget_min=rb, intel=intel, send_thinking=True, self_assess=False, stop_event=stop_event, direction='RECON ONLY: fingerprint product/version, crawl + dir scan + nuclei; record EVERY finding as notes(kind=fact). Do not exploit unless the flag is trivially exposed.', dead_ends=dead_ends)
            except Exception as e:
                events.log('solve_error', code=code, error=str(e)[:200])
            rsnap = notes.snapshot(20)
            if rsnap and rsnap != '(no notes yet)':
                intel = (rsnap + ('\n' + intel if intel else ''))[:1500]
        events.log('challenge_start', code=code, phase='GLM' if use_glm else 'flash', peers=n_peers, budget_min=round(budget, 1), seeded=bool(intel), hint=bool(hint))
        outcomes = []
        threads = []
        for i in range(n_peers):
            if n_peers > 1 and glm_ok:
                peer_glm = i % 2 == 1
            else:
                peer_glm = use_glm and glm_ok
            llm_inst = llm_glm if peer_glm else llm
            if hasattr(llm_inst, 'set_challenge'):
                llm_inst.set_challenge(code)
            direction = PEER_DIRECTIONS[i % len(PEER_DIRECTIONS)] if n_peers > 1 else None

            def run_peer(_llm=llm_inst, _dir=direction, _glm=peer_glm):
                try:
                    outcomes.append(agentmod.solve_challenge(chd, addrs, cfg, _llm, notes, submit_logged, events, wd, budget_min=budget, hint=hint, intel=intel, send_thinking=not _glm, self_assess=_glm, stop_event=stop_event, direction=_dir, dead_ends=dead_ends))
                except Exception as e:
                    events.log('solve_error', code=code, error=str(e)[:200])
            t = threading.Thread(target=run_peer, daemon=True)
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=budget * 60 + 120)
        cs.facts = notes.facts_count()
        cs.flags = flag_counts.get(code, 0)
        cs.status = SOLVED if cs.flags >= ch.flag_count else PARTIAL if cs.flags > 0 else FAILED
        cs.steps = sum((getattr(o, 'steps', 0) for o in outcomes))
        cs.elapsed = max((getattr(o, 'elapsed', 0) for o in outcomes), default=0)
        if cs.status != SOLVED:
            cs.intel = notes.snapshot(12)[:1500]
        else:
            facts = [e['content'] for e in notes.entries if e.get('kind') == 'fact'][:6]
            kb.add(code, {'difficulty': cs.difficulty, 'flags': cs.flags, 'facts': facts})
        if glm_ok and getattr(llm_glm, 'exhausted', False) and (not glm_disabled.is_set()):
            glm_disabled.set()
            events.log('escalation_disabled', reason='glm_quota_exhausted')
        events.log('challenge_end', code=code, status=cs.status, peers=n_peers, steps=cs.steps, glm=use_glm)
        life.close(code)
        state.save()

    def claim():
        try:
            return (fresh_q.get_nowait(), False)
        except queue.Empty:
            pass
        try:
            return (retry_q.get_nowait(), True)
        except queue.Empty:
            return (None, False)

    def slot_worker():
        nonlocal in_flight
        while not stop.is_set() and time.time() < deadline:
            ch, use_glm = claim()
            if ch is None:
                with in_flight_lock:
                    idle = in_flight == 0 and fresh_q.empty() and retry_q.empty()
                if idle:
                    return
                time.sleep(2)
                continue
            cs = state.get(ch.unique_code)
            if cs.status == SOLVED:
                continue
            with in_flight_lock:
                in_flight += 1
            try:
                run_challenge(ch, peers_for(use_glm), use_glm)
                cs = state.get(ch.unique_code)
                if cs.status != SOLVED and cs.attempts < max_attempts and (cs.facts > 0 or cs.attempts < 2):
                    retry_q.put(ch)
            except InvalidState as e:
                msg = str(getattr(e, 'message', e))
                if 'max active' in msg:
                    events.log('max_active_wait', code=ch.unique_code)
                    retry_q.put(ch)
                    time.sleep(5)
                else:
                    events.log('task_ended', msg=msg[:200])
                    stop.set()
                    return
            except Exception as e:
                events.log('worker_error', error=str(e)[:200])
                retry_q.put(ch)
            finally:
                with in_flight_lock:
                    in_flight -= 1
    slots = [threading.Thread(target=slot_worker, daemon=True) for _ in range(max(1, cfg.pool))]
    for t in slots:
        t.start()
    for t in slots:
        t.join()
    life.close_all()
    report_path = generate(state, llm.budget.totals(), events.path)
    events.log('run_end', report=report_path)
    return report_path

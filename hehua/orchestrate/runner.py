"""Main run loop: R1 sweep -> R2 second pass -> optional GLM escalation -> report.

Heterogeneous pool (run-xben directive): with GLM_API_KEY set, run 2 flash
workers for breadth plus 1 GLM-5.2 escalation worker that re-attempts whatever
flash could not solve. Without a GLM key it degrades to the normal flash pool.
Containers are always closed.
"""
from __future__ import annotations

import os
import queue
import threading
import time
from dataclasses import asdict
from pathlib import Path

from tsec_benchmark import InvalidState

from ..core import agent as agentmod
from ..core.memory import Notes
from ..metrics.report import generate
from . import scheduler
from .lifecycle import Lifecycle
from .state import FAILED, PARTIAL, SKIPPED, SOLVED, State


def _build_esc_llm(cfg, budget):
    """Dedicated GLM-5.2 client for escalation; None without GLM_API_KEY.

    Uses the OpenAI-compatible Zhipu endpoint (verified tool-call compatible)
    and SHARES the caller's Budget so token accounting stays unified.
    gateway=False: open.bigmodel.cn is not on the hosted-sandbox whitelist —
    escalation is a local-mode capability."""
    if not cfg.glm_api_key:
        return None
    from ..llm.client import LLMClient
    from ..llm.registry import Provider
    prov = Provider("glm-esc", "https://open.bigmodel.cn/api/paas/v4",
                    cfg.glm_api_key, cfg.glm_model)
    return LLMClient([prov], budget, gateway=False)


def run(cfg, platform_client, llm, events, state: State,
        workdir_root: str = "out") -> str:
    life = Lifecycle(platform_client, events)
    life.cleanup_orphans(state)
    challenges = [c for c in life.list_challenges() if not c.is_completed]
    events.log("run_start", n_challenges=len(challenges), mode=cfg.mode)

    deadline = time.time() + cfg.net_budget_min * 60
    workroot = Path(workdir_root)
    flag_counts: dict[str, int] = {}

    # Escalation is a LOCAL-mode capability: mock keeps smoke offline, and the
    # hosted sandbox has no public internet so open.bigmodel.cn is unreachable.
    llm_esc = None if (cfg.mock_llm or cfg.model_gateway) \
        else _build_esc_llm(cfg, llm.budget)
    esc_on = llm_esc is not None
    if esc_on:
        events.log("escalation_enabled", model=cfg.glm_model)

    def attempt(ch, budget_min: float, hint: str | None = None,
                intel: str | None = None, llm_inst=None,
                send_thinking: bool = True) -> None:
        llm_inst = llm_inst or llm
        cs = state.get(ch.unique_code)
        cs.flag_count = ch.flag_count
        cs.difficulty = getattr(ch, "difficulty", "unknown") or "unknown"
        # Start the container BEFORE counting the attempt: a platform start
        # failure (502/503 docker-compose) must not burn one of the two tries
        # or leave the challenge stuck in 'running' (run-xben observation).
        try:
            started = life.start(ch, scheduler.priority)
        except Exception as e:  # noqa: BLE001 — start failures are retryable
            events.log("start_error", code=ch.unique_code, error=str(e)[:200])
            cs.status = FAILED
            state.save()
            return
        if started is None:
            cs.status = SKIPPED
            state.save()
            return
        cs.attempts += 1
        cs.status = "running"
        state.save()
        if hasattr(llm_inst, "set_challenge"):  # mock LLM hook
            llm_inst.set_challenge(ch.unique_code)
        try:
            wd = workroot / ch.unique_code
            wd.mkdir(parents=True, exist_ok=True)
            notes = Notes(wd / "notes.jsonl")

            def submit_logged(flag, writeup=""):
                r = life.submit(ch, flag, writeup)
                events.log("submit", code=ch.unique_code, flag=flag,
                           correct=r["correct"], remaining=r["remaining"])
                if r["correct"]:
                    got = max(0, ch.flag_count - r["remaining"])
                    flag_counts[ch.unique_code] = max(
                        flag_counts.get(ch.unique_code, 0), got)
                return r

            try:
                outcome = agentmod.solve_challenge(
                    asdict(ch) if hasattr(ch, "__dataclass_fields__") else dict(ch),
                    list(started.container_addr), cfg, llm_inst, notes,
                    submit_logged, events, wd, budget_min=budget_min, hint=hint,
                    intel=intel, send_thinking=send_thinking)
                cs.elapsed += outcome.elapsed
                cs.gave_up = outcome.gave_up
                cs.steps = outcome.steps
            except Exception as e:  # noqa: BLE001 — per-challenge resilience
                events.log("solve_error", code=ch.unique_code, error=str(e)[:300])
                outcome = None
            cs.facts = notes.facts_count()
            cs.flags = flag_counts.get(ch.unique_code, 0)
            cs.status = SOLVED if cs.flags >= ch.flag_count else (
                PARTIAL if cs.flags > 0 else FAILED)
            # carry breakthrough intel into any retry (round-2 lesson:
            # agents die ONE STEP short — retries must start at the kill chain)
            if cs.status != SOLVED and outcome:
                cs.intel = (notes.snapshot(12) + "\n" +
                            (outcome.summary or ""))[:1500]
            events.log("challenge_end", code=ch.unique_code, status=cs.status,
                       steps=getattr(outcome, "steps", 0),
                       elapsed=getattr(outcome, "elapsed", 0),
                       gave_up=getattr(outcome, "gave_up", True))
        finally:
            life.close(ch.unique_code)
            state.save()

    # ---- two-pass priority sweep ----
    # pass@2 >> pass@1 on public data; R2 is baked into the same queue.
    # coverage-first: every UNTRIED challenge gets attempt #1 before any retry.
    ordered = scheduler.order(challenges)
    untried = [c for c in ordered if state.get(c.unique_code).attempts == 0]
    q: queue.Queue = queue.Queue()
    for item in [("R1", c) for c in untried] + [("R2", c) for c in ordered]:
        q.put(item)
    stop = threading.Event()
    pool = max(1, int(os.getenv("HEHUA_POOL", "2")))
    # With escalation on, reserve one container slot for the GLM worker so the
    # 2 flash + 1 GLM workers never exceed the platform max-active of 3.
    n_flash = max(1, pool - 1) if esc_on else pool

    esc_q: queue.Queue = queue.Queue()
    escalated: set = set()
    esc_lock = threading.Lock()

    def _maybe_escalate(ch) -> None:
        """Hand a challenge flash has given up on to the GLM worker. Only once
        flash will not retry it again (avoids racing flash's own R2 attempt)."""
        cs = state.get(ch.unique_code)
        if not (esc_on and cs.status in (FAILED, PARTIAL)) or stop.is_set():
            return
        will_retry = (cs.attempts == 1 and
                      scheduler.retry_eligible(ch, state))
        if will_retry:
            return
        with esc_lock:
            if ch.unique_code not in escalated:
                escalated.add(ch.unique_code)
                esc_q.put(ch)
                events.log("escalated", code=ch.unique_code, to="glm")

    def flash_worker() -> None:
        while not stop.is_set():
            try:
                phase, ch = q.get_nowait()
            except queue.Empty:
                return
            try:
                if time.time() > deadline:
                    events.log("deadline", phase=phase)
                    continue
                cs = state.get(ch.unique_code)
                if cs.status == SOLVED or cs.attempts >= 2:
                    continue
                if cs.attempts == 1 and not scheduler.retry_eligible(ch, state):
                    continue  # low-prior classes: one shot unless progress made
                budget = min(scheduler.budget_for(ch, cfg),
                             max(2.0, (deadline - time.time()) / 60))
                if cs.attempts == 1:
                    budget = max(2.0, budget * 0.7)  # retries get 70% budget
                hint = life.hint(ch) if cs.attempts == 1 else None
                events.log("challenge_start", code=ch.unique_code, phase=phase,
                           budget_min=round(budget, 1), hint=bool(hint),
                           seeded=bool(cs.intel))
                attempt(ch, budget, hint=hint, intel=cs.intel or None)
                _maybe_escalate(ch)
            except InvalidState as e:  # platform task ended -> graceful stop
                events.log("task_ended", msg=str(getattr(e, "message", e))[:200])
                stop.set()
                return
            except Exception as e:  # noqa: BLE001 — a worker must not die silently
                events.log("worker_error", error=str(e)[:200])

    def glm_worker() -> None:
        while True:
            ch = esc_q.get()          # blocks until an escalation or sentinel
            if ch is None or stop.is_set():
                return
            try:
                cs = state.get(ch.unique_code)
                if cs.status == SOLVED or time.time() > deadline:
                    continue
                budget = min(scheduler.budget_for(ch, cfg),
                             max(2.0, (deadline - time.time()) / 60))
                events.log("challenge_start", code=ch.unique_code, phase="GLM",
                           budget_min=round(budget, 1), hint=False,
                           seeded=bool(cs.intel))
                attempt(ch, budget, hint=None, intel=cs.intel or None,
                        llm_inst=llm_esc, send_thinking=False)
            except InvalidState as e:
                events.log("task_ended", msg=str(getattr(e, "message", e))[:200])
                stop.set()
                return
            except Exception as e:  # noqa: BLE001
                events.log("worker_error", error=str(e)[:200])

    flash_threads = [threading.Thread(target=flash_worker, daemon=True)
                     for _ in range(n_flash)]
    esc_thread = (threading.Thread(target=glm_worker, daemon=True)
                  if esc_on else None)
    for t in flash_threads:
        t.start()
    if esc_thread:
        esc_thread.start()
    for t in flash_threads:
        t.join()
    if esc_thread:
        esc_q.put(None)               # sentinel: stop GLM once escalations drain
        esc_thread.join()

    life.close_all()
    report_path = generate(state, llm.budget.totals(), events.path)
    events.log("run_end", report=report_path)
    return report_path

"""Scheduler: prefix-aware ordering, calibrated budgets, R2 queue."""
from types import SimpleNamespace as Ch

from hehua.config import Config
from hehua.orchestrate import scheduler
from hehua.orchestrate.state import FAILED, PARTIAL, SKIPPED, SOLVED, State


def ch(code, score=100, diff="medium"):
    return Ch(unique_code=code, total_score=score, difficulty=diff, flag_count=1)


def test_order_ev_per_minute():
    # equal scores: EV = prior/budget -> e(23.8) > f1(20) > d(17) > a(8.8)
    # > f2(7.1) > c(3.7) > b(1.0)
    cs = [ch("a-01"), ch("e1-01"), ch("b-01"), ch("d-01"), ch("f2-01"),
          ch("f1-01"), ch("c-01"), ch("e3-04")]
    got = [c.unique_code for c in scheduler.order(cs)]
    assert got == ["e1-01", "e3-04", "f1-01", "d-01", "a-01", "f2-01",
                   "c-01", "b-01"]


def test_retry_eligibility():
    st = State()
    st.get("a-07").facts = 0
    st.get("a-09").facts = 3
    st.get("f2-03").facts = 0
    st.get("c-04").facts = 0
    assert not scheduler.retry_eligible(ch("a-07"), st)   # low prior, no progress
    assert scheduler.retry_eligible(ch("a-09"), st)       # progress recorded
    assert scheduler.retry_eligible(ch("f2-03"), st)      # quick class
    assert scheduler.retry_eligible(ch("c-04"), st)       # run-6661: c retries unconditional
    # non-platform (blind) sets retry even with zero facts — pass@2 >> pass@1
    assert scheduler.retry_eligible(ch("xben-026-24"), st)
    assert not scheduler.retry_eligible(ch("b-02"), st)   # platform killchain still gated by facts


def test_budgets_calibrated():
    cfg = Config()
    assert scheduler.budget_for(ch("e1-01"), cfg) == 6
    assert scheduler.budget_for(ch("d-01"), cfg) == 8
    assert scheduler.budget_for(ch("f1-01"), cfg) == 8
    assert scheduler.budget_for(ch("a-01"), cfg) == 12
    assert scheduler.budget_for(ch("c-01"), cfg) == 25
    assert scheduler.budget_for(ch("f2-01"), cfg) == 18
    assert scheduler.budget_for(ch("b-01"), cfg) == 50


def test_budget_fallback_difficulty():
    cfg = Config()
    assert scheduler.budget_for(ch("z-99", diff="easy"), cfg) == 4
    assert scheduler.budget_for(ch("z-99", diff="hard"), cfg) == 15


def test_unknown_prefix_orders_easy_first():
    # XBOW-style blind set ('xben-*'): no calibrated prefix, so priority must
    # divide by the difficulty budget -> cheap easy challenges rank first.
    cs = [ch("xben-001-24", score=500, diff="hard"),
          ch("xben-002-24", score=300, diff="medium"),
          ch("xben-003-24", score=200, diff="easy"),
          ch("xben-004-24", score=300, diff="medium")]
    got = [c.unique_code for c in scheduler.order(cs)]
    assert got[0] == "xben-003-24"        # easy 200/4 = 25 first
    assert got[-1] == "xben-001-24"       # hard 500/15 ~16.7 last
    # platform prefixes unaffected: still calibrated PREFIX_BUDGET divisor
    assert scheduler.order([ch("e1-01"), ch("a-01")])[0].unique_code == "e1-01"


def test_full_slate_fits_3worker_capacity():
    # 3 workers x 315 net = 945 worker-min; full 63-challenge slate ~907
    cfg = Config()
    cs = ([ch(f"e1-0{i}") for i in range(1, 7)] + [ch(f"e2-0{i}") for i in range(1, 5)]
          + [ch(f"e3-0{i}") for i in range(1, 5)] + [ch(f"d-0{i}") for i in range(1, 7)]
          + [ch(f"f1-0{i}") for i in range(1, 6)] + [ch(f"f2-0{i}") for i in range(1, 9)]
          + [ch(f"a-{i:02d}") for i in range(1, 19)] + [ch(f"c-0{i}") for i in range(1, 10)]
          + [ch(f"b-0{i}") for i in range(1, 4)])
    total = sum(scheduler.budget_for(c, cfg) for c in cs)
    assert total <= 3 * cfg.net_budget_min


def test_r2_queue_rules():
    st = State()
    st.get("solved").status = SOLVED
    st.get("part").status = PARTIAL
    st.get("prog").status = FAILED
    st.get("prog").facts = 3
    st.get("dead").status = FAILED     # no facts -> not retried
    st.get("skip").status = SKIPPED
    cs = [ch(c) for c in ("solved", "part", "prog", "dead", "skip")]
    got = set(c.unique_code for c in scheduler.r2_queue(cs, st))
    assert got == {"part", "prog", "skip"}

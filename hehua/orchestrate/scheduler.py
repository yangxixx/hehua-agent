"""Deterministic scheduler: prefix-aware ordering (leaderboard-calibrated),
per-class budgets, R2 second-pass queue.

Calibration source: docs/leaderboard-intel.md (65 public eval runs).
Challenge codes on Tsecbench v1 use dimension prefixes:
  a- Web(18)  b- killchain(3, multi-flag)  c- exploit(9)  d- cloud(6)
  e1/e2/e3- evasion(14)  f1/f2- binary(13)
Observed ROI (flags-per-minute across top agents) drives priority:
evasion/cloud/f1 are near-free points; Web bulk next; killchain for partial
credit; exploit/f2 last.
"""
from __future__ import annotations

from .state import FAILED, PARTIAL, SKIPPED, SOLVED, State

DIFF_COEFF = {"easy": 1.0, "medium": 1.6, "hard": 2.5}

# solve-probability priors per class, from the public per-challenge matrices
# (Excalibur/BreachWeave on deepseek): how often top agents solve this class.
PRIOR = {"e1": 0.95, "e2": 0.95, "e3": 0.90, "d": 0.85, "f1": 1.00,
         "f2": 0.85, "a": 0.70, "c": 0.55, "b": 0.35}
# classes where a second attempt is allowed unconditionally (high prior);
# others retry only with recorded progress (round-0 postmortem: hard-a
# retries burned 111min and starved c/f2 entirely).
# run-6661 lesson: c- classes carry the HIGHEST final-score value per flag
# (15% weight on the smallest dim base ≈ 3.75 final pts per 500-pt flag),
# yet c-04 died once at 5.6min with 0 facts and never retried. c- retries
# are now unconditional; the gate below still protects a-/b- budgets.
QUICK_RETRY = {"e1", "e2", "e3", "d", "f1", "f2", "c"}

# Platform dimension prefixes with calibrated budgets/priors. Any OTHER prefix
# (e.g. the XBOW 'xben-*' blind set) is treated as retry-friendly: a second,
# different approach often solves what the first missed (pass@2 >> pass@1), and
# failed blind challenges otherwise get locked out by the facts==0 gate.
_PLATFORM_PREFIXES = {"a", "b", "c", "d", "e1", "e2", "e3", "f1", "f2"}
# minutes per challenge class, from observed top-agent solve times.
# per-challenge minutes (3-worker build: 3x315=945 worker-min capacity,
# full slate at these budgets ~=907)
PREFIX_BUDGET = {"e1": 6, "e2": 6, "e3": 6, "d": 8, "f1": 8,
                 "a": 12, "b": 50, "c": 25, "f2": 18}


def prefix_of(code: str) -> str:
    for p in ("e1", "e2", "e3", "f1", "f2"):
        if code.startswith(p):
            return p
    return (code or "?")[:1]


_PRIORS_CACHE: dict | None = None


def get_priors() -> dict:
    """Public priors overlaid with self-calibrated rates (priors.json)."""
    global _PRIORS_CACHE
    if _PRIORS_CACHE is None:
        _PRIORS_CACHE = dict(PRIOR)
        import json, os
        try:
            with open(os.getenv("HEHUA_PRIORS", "priors.json"),
                      encoding="utf-8") as f:
                _PRIORS_CACHE.update(json.load(f))
        except (OSError, ValueError):
            pass
    return _PRIORS_CACHE


def reset_priors() -> None:
    global _PRIORS_CACHE
    _PRIORS_CACHE = None


def priority(ch) -> float:
    """Expected-value ordering: P(solve) * score / minutes (round-0 lesson)."""
    pre = prefix_of(ch.unique_code)
    p = get_priors().get(pre, 0.5)
    div = PREFIX_BUDGET.get(pre)
    if div is None:
        # Unknown prefix (e.g. XBOW 'xben-*' blind set): divide by the
        # difficulty budget the challenge will actually receive, so cheap
        # easy challenges rank first ("先拿能拿的分"). Platform prefixes keep
        # the calibrated PREFIX_BUDGET divisor unchanged.
        div = _LEVEL_DIV.get((getattr(ch, "difficulty", "") or "").lower(),
                             _LEVEL_DIV["default"])
    return p * ch.total_score / div


def order(challenges: list) -> list:
    return sorted(challenges, key=lambda c: (priority(c), c.total_score),
                  reverse=True)


def retry_eligible(ch, state) -> bool:
    cs = state.get(ch.unique_code)
    pre = prefix_of(ch.unique_code)
    # quick classes retry unconditionally; non-platform (blind) sets too;
    # calibrated platform classes retry only when progress was recorded.
    return pre in QUICK_RETRY or pre not in _PLATFORM_PREFIXES or cs.facts > 0


DIFF_FACTOR = {"easy": 0.6, "medium": 1.0, "hard": 1.0}

# per-difficulty minutes for challenges with no calibrated prefix budget
# (mirrors Config.level_budget_min); used as the priority divisor for
# unknown-prefix sets so cheap easy challenges sort first.
_LEVEL_DIV = {"easy": 4.0, "medium": 8.0, "hard": 15.0, "default": 8.0}


def budget_for(ch, cfg) -> float:
    pb = PREFIX_BUDGET.get(prefix_of(ch.unique_code))
    if pb is not None:
        return float(pb) * DIFF_FACTOR.get((ch.difficulty or "").lower(), 1.0)
    return float(cfg.level_budget_min.get((ch.difficulty or "").lower(),
                                          cfg.level_budget_min["default"]))


def r2_queue(challenges: list, state: State) -> list:
    """Second pass targets: progress-but-unsolved / partial flags / skipped."""
    out = []
    for ch in challenges:
        cs = state.get(ch.unique_code)
        if cs.status == SOLVED:
            continue
        if cs.status == PARTIAL:
            out.append(ch)
        elif cs.status == FAILED and cs.facts > 0:
            out.append(ch)
        elif cs.status == SKIPPED:
            out.append(ch)
    return order(out)

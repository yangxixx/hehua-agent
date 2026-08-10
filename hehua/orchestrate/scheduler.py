from __future__ import annotations
from .state import FAILED, PARTIAL, SKIPPED, SOLVED, State
DIFF_COEFF = {'easy': 1.0, 'medium': 1.6, 'hard': 2.5}
PRIOR = {'e1': 0.95, 'e2': 0.95, 'e3': 0.9, 'd': 0.85, 'f1': 1.0, 'f2': 0.85, 'a': 0.7, 'c': 0.55, 'b': 0.35}
QUICK_RETRY = {'e1', 'e2', 'e3', 'd', 'f1', 'f2', 'c'}
_PLATFORM_PREFIXES = {'a', 'b', 'c', 'd', 'e1', 'e2', 'e3', 'f1', 'f2'}
PREFIX_BUDGET = {'e1': 6, 'e2': 6, 'e3': 6, 'd': 8, 'f1': 8, 'a': 12, 'b': 50, 'c': 25, 'f2': 18}

def prefix_of(code: str) -> str:
    for p in ('e1', 'e2', 'e3', 'f1', 'f2'):
        if code.startswith(p):
            return p
    return (code or '?')[:1]
_PRIORS_CACHE: dict | None = None

def get_priors() -> dict:
    global _PRIORS_CACHE
    if _PRIORS_CACHE is None:
        _PRIORS_CACHE = dict(PRIOR)
        import json, os
        try:
            with open(os.getenv('HEHUA_PRIORS', 'priors.json'), encoding='utf-8') as f:
                _PRIORS_CACHE.update(json.load(f))
        except (OSError, ValueError):
            pass
    return _PRIORS_CACHE

def reset_priors() -> None:
    global _PRIORS_CACHE
    _PRIORS_CACHE = None

def priority(ch) -> float:
    pre = prefix_of(ch.unique_code)
    p = get_priors().get(pre, 0.5)
    div = PREFIX_BUDGET.get(pre)
    if div is None:
        div = _LEVEL_DIV.get((getattr(ch, 'difficulty', '') or '').lower(), _LEVEL_DIV['default'])
    return p * ch.total_score / div

def order(challenges: list) -> list:
    return sorted(challenges, key=lambda c: (priority(c), c.total_score), reverse=True)

def retry_eligible(ch, state) -> bool:
    cs = state.get(ch.unique_code)
    pre = prefix_of(ch.unique_code)
    return pre in QUICK_RETRY or pre not in _PLATFORM_PREFIXES or cs.facts > 0
DIFF_FACTOR = {'easy': 0.6, 'medium': 1.0, 'hard': 1.0}
_LEVEL_DIV = {'easy': 4.0, 'medium': 8.0, 'hard': 15.0, 'default': 8.0}

def budget_for(ch, cfg) -> float:
    pb = PREFIX_BUDGET.get(prefix_of(ch.unique_code))
    if pb is not None:
        return float(pb) * DIFF_FACTOR.get((ch.difficulty or '').lower(), 1.0)
    return float(cfg.level_budget_min.get((ch.difficulty or '').lower(), cfg.level_budget_min['default']))

def r2_queue(challenges: list, state: State) -> list:
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

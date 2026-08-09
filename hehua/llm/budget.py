"""Token/cost accounting per model (feeds BSRC metrics: 大模型运行成本)."""
from __future__ import annotations

import threading


class Budget:
    def __init__(self, soft_limit: int = 150_000_000):
        self.soft_limit = soft_limit
        self._lock = threading.Lock()
        self._by_model: dict[str, dict[str, int]] = {}

    def record(self, model: str, prompt_tokens: int, completion_tokens: int) -> None:
        with self._lock:
            m = self._by_model.setdefault(
                model, {"prompt": 0, "completion": 0, "calls": 0})
            m["prompt"] += int(prompt_tokens or 0)
            m["completion"] += int(completion_tokens or 0)
            m["calls"] += 1

    def totals(self) -> dict:
        with self._lock:
            prompt = sum(m["prompt"] for m in self._by_model.values())
            comp = sum(m["completion"] for m in self._by_model.values())
            return {
                "prompt_tokens": prompt,
                "completion_tokens": comp,
                "total_tokens": prompt + comp,
                "by_model": {k: dict(v) for k, v in self._by_model.items()},
            }

    def over_soft_limit(self) -> bool:
        return self.totals()["total_tokens"] >= self.soft_limit

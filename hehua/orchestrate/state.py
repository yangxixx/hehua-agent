"""Checkpoint state for resume-after-kill (断点续跑)."""
from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

PENDING, RUNNING, SOLVED, PARTIAL, FAILED, SKIPPED = (
    "pending", "running", "solved", "partial", "failed", "skipped")


@dataclass
class ChallengeState:
    code: str
    status: str = PENDING
    attempts: int = 0
    flags: int = 0
    flag_count: int = 0
    elapsed: float = 0.0
    facts: int = 0
    error: str = ""
    difficulty: str = "unknown"
    gave_up: bool = False
    steps: int = 0
    intel: str = ""


@dataclass
class State:
    path: Path = field(default_factory=lambda: Path("state/state.json"))
    challenges: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock,
                                  repr=False, compare=False)

    def get(self, code: str) -> ChallengeState:
        with self._lock:
            return self.challenges.setdefault(code, ChallengeState(code))

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {c: asdict(s) for c, s in self.challenges.items()}
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)

    @classmethod
    def load(cls, path: str | Path = "state/state.json") -> "State":
        st = cls(path=Path(path))
        if st.path.exists():
            try:
                raw = json.loads(st.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                raw = {}
            for code, d in raw.items():
                st.challenges[code] = ChallengeState(**d)
        return st

from __future__ import annotations
import threading
import time
from tsec_benchmark import DuplicateSubmit, InvalidState, ResourceUnavailable
RETRY_BACKOFF = (2, 5, 10)

class Lifecycle:

    def __init__(self, client, events=None):
        self.client = client
        self.events = events
        self.open: dict[str, object] = {}
        self._lock = threading.Lock()

    def list_challenges(self):
        return self.client.list_challenges()

    def start(self, ch, value_fn=None):
        for i in range(4):
            try:
                started = self.client.start_challenge(ch.unique_code)
                with self._lock:
                    self.open[ch.unique_code] = ch
                return started
            except ResourceUnavailable:
                if i == 3:
                    raise
                time.sleep(RETRY_BACKOFF[i])
            except InvalidState as e:
                if 'max active' not in str(e.message if hasattr(e, 'message') else e):
                    raise
                victim = self._pick_victim(value_fn, except_code=ch.unique_code)
                if victim:
                    self.close(victim)
        return None

    def _pick_victim(self, value_fn, except_code):
        with self._lock:
            if not self.open:
                return None
            if value_fn is None:
                victim = next(iter(self.open))
            else:
                victim = min(self.open, key=lambda c: value_fn(self.open[c]))
            return None if victim == except_code else victim

    def submit(self, ch, flag, writeup='') -> dict:
        try:
            r = self.client.submit_flag(ch.unique_code, flag)
            return {'correct': bool(r.correct), 'remaining': max(0, r.total_flag_count - r.correct_flag_count), 'awarded': getattr(r, 'awarded', 0)}
        except DuplicateSubmit:
            return {'correct': True, 'remaining': max(0, ch.flag_count - 1), 'awarded': 0}

    def hint(self, ch) -> str | None:
        try:
            r = self.client.get_hint(ch.unique_code)
            return getattr(r, 'hint', None)
        except Exception:
            return None

    def close(self, code: str) -> None:
        try:
            self.client.close_challenge(code)
        except Exception:
            pass
        with self._lock:
            self.open.pop(code, None)

    def close_all(self) -> None:
        with self._lock:
            codes = list(self.open)
        for code in codes:
            self.close(code)

    def cleanup_orphans(self, state) -> None:
        for code, cs in state.challenges.items():
            if cs.status == 'running':
                self.close(code)
                cs.status = 'pending'
                cs.attempts = max(0, cs.attempts - 1)

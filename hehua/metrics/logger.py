from __future__ import annotations
import json
import threading
import time
from pathlib import Path

class EventLogger:

    def __init__(self, path: str | Path='logs/events.jsonl'):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, etype: str, **fields) -> None:
        rec = {'ts': time.strftime('%Y-%m-%d %H:%M:%S'), 'type': etype, **fields}
        with self._lock:
            with self.path.open('a', encoding='utf-8') as f:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')

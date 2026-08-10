from __future__ import annotations
import json
import threading
from pathlib import Path
KINDS = ('idea', 'fact', 'failure', 'todo')

class Notes:

    def __init__(self, path: str | Path | None=None):
        self.path = Path(path) if path else None
        self.entries: list[dict] = []
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            for line in self.path.read_text(encoding='utf-8').splitlines():
                if line.strip():
                    try:
                        self.entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    def add(self, kind: str, content: str) -> str:
        if kind not in KINDS:
            kind = 'fact'
        entry = {'kind': kind, 'content': str(content)[:220]}
        with self._lock:
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open('a', encoding='utf-8') as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        return f"noted [{kind}] {entry['content']}"

    def snapshot(self, limit: int=40) -> str:
        with self._lock:
            recent = self.entries[-limit:]
        if not recent:
            return '(no notes yet)'
        lines = [f"- [{e['kind']}] {e['content']}" for e in recent]
        return '\n'.join(lines)

    def facts_count(self) -> int:
        return sum((1 for e in self.entries if e['kind'] == 'fact'))

    def has_open_idea(self) -> bool:
        return any((e['kind'] == 'idea' for e in self.entries[-10:]))

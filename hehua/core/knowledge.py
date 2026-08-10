from __future__ import annotations
import json
import threading
from pathlib import Path

def family_of(code: str) -> str:
    c = (code or '').lower()
    for p in ('e1', 'e2', 'e3', 'f1', 'f2'):
        if c.startswith(p):
            return p
    return c[:1] or '?'

class Knowledge:

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.entries: list[dict] = []
        if self.path.exists():
            for line in self.path.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self.entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    def add(self, code: str, recipe: dict) -> dict:
        entry = {'code': code, 'family': family_of(code), **recipe}
        with self._lock:
            self.entries.append(entry)
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open('a', encoding='utf-8') as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            except OSError:
                pass
        return entry

    def siblings(self, family: str, limit: int=8) -> list[dict]:
        return [e for e in self.entries if e.get('family') == family][-limit:]

    def seed_from(self, path) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        seen = {e.get('code') for e in self.entries}
        n = 0
        with self._lock:
            for line in p.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get('code') not in seen:
                    self.entries.append(e)
                    seen.add(e.get('code'))
                    n += 1
        return n

    def intel_block(self, family: str, limit: int=6) -> str | None:
        sib = [e for e in self.entries if e.get('family') == family][-limit:]
        if not sib:
            return None
        lines = []
        for e in sib:
            parts = [f"[{e.get('code')}]"]
            for k in ('product', 'cve', 'auth', 'payload', 'flag_loc'):
                v = e.get(k)
                if v:
                    parts.append(f'{k}={v}')
            facts = e.get('facts') or []
            if facts:
                parts.append('facts=' + ' | '.join((str(f) for f in facts[:3])))
            lines.append(' · '.join(parts))
        return '\n'.join(lines)

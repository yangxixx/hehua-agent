"""Cross-challenge recipe knowledge base (a top agent's signature pattern).

a top agent  reuses prior solves: when attacking a
challenge it reads scripts/flags from already-solved SIBLINGS
(/workspace/runtime/<code>/solve/...). We mirror that with a shared
knowledge.jsonl in the workroot: every solved challenge writes a short recipe
(product / CVE / proven payload / flag location), and each new challenge is
seeded with its family's prior recipes as intel — so a working PoC for c-02
becomes a head-start for c-03, etc.

The file persists in the mounted out/ volume, so knowledge accumulates BOTH
within a run and across runs (resume / pre-seeded for 8/16). Thread-safe
(multiple workers append).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path


def family_of(code: str) -> str:
    """Dimension prefix; mirrors scheduler.prefix_of so KB families line up
    with scheduling priors. a/b/c/d → first letter; e1/e2/e3/f1/f2 → 2-char;
    XBOW 'xben-*' → 'x' (siblings grouped); empty → '?'."""
    c = (code or "").lower()
    for p in ("e1", "e2", "e3", "f1", "f2"):
        if c.startswith(p):
            return p
    return c[:1] or "?"


class Knowledge:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.entries: list[dict] = []
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self.entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    def add(self, code: str, recipe: dict) -> dict:
        """Append a solved-case recipe (thread-safe). recipe carries family,
        product/cve/payload/flag_loc/facts — whatever the caller distilled."""
        entry = {"code": code, "family": family_of(code), **recipe}
        with self._lock:
            self.entries.append(entry)
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except OSError:
                pass  # knowledge is best-effort; never break a solve on it
        return entry

    def siblings(self, family: str, limit: int = 8) -> list[dict]:
        return [e for e in self.entries if e.get("family") == family][-limit:]

    def seed_from(self, path) -> int:
        """Load a baked seed (from scripts/learn.py, copied into the image) into
        memory without writing to the runtime file — so a fresh run starts with
        prior-run recipes. Dedups by code. Returns count loaded."""
        p = Path(path)
        if not p.exists():
            return 0
        seen = {e.get("code") for e in self.entries}
        n = 0
        with self._lock:
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("code") not in seen:
                    self.entries.append(e)
                    seen.add(e.get("code"))
                    n += 1
        return n

    def intel_block(self, family: str, limit: int = 6) -> str | None:
        """Render prior same-family solves as an injection for a new challenge.
        None if no relevant knowledge yet."""
        sib = [e for e in self.entries if e.get("family") == family][-limit:]
        if not sib:
            return None
        lines = []
        for e in sib:
            parts = [f"[{e.get('code')}]"]
            for k in ("product", "cve", "auth", "payload", "flag_loc"):
                v = e.get(k)
                if v:
                    parts.append(f"{k}={v}")
            facts = e.get("facts") or []
            if facts:
                parts.append("facts=" + " | ".join(str(f) for f in facts[:3]))
            lines.append(" · ".join(parts))
        return "\n".join(lines)

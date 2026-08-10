#!/usr/bin/env python3
"""Backfill the cross-challenge KB from already-solved challenges' notes.

Reads <run_dir>/state/state.json + <run_dir>/out/<code>/notes.jsonl, extracts
fact-recipes for SOLVED challenges, and writes <run_dir>/out/knowledge.jsonl.

Use cases:
  - recover recipes for solves that happened before the KB feature existed
    (so later siblings still benefit mid-run);
  - pre-seed the 8/16 competition KB from a completed practice run
    (copy the resulting knowledge.jsonl into the image / mount it).

Usage: python seed_knowledge.py <run_dir>   # run_dir contains state/ and out/
"""
import json
import sys
from pathlib import Path


def family_of(code: str) -> str:
    c = (code or "").lower()
    for p in ("e1", "e2", "e3", "f1", "f2"):
        if c.startswith(p):
            return p
    return c[:1] or "?"


def main(run_dir: str) -> int:
    run = Path(run_dir)
    state = json.loads((run / "state" / "state.json").read_text(encoding="utf-8"))
    kb_path = run / "out" / "knowledge.jsonl"
    recipes = []
    for code, cs in state.items():
        if cs.get("status") != "solved":
            continue
        facts = []
        nf = run / "out" / code / "notes.jsonl"
        if nf.exists():
            for line in nf.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("kind") == "fact":
                    facts.append(e.get("content", ""))
        recipes.append({"code": code, "family": family_of(code),
                        "difficulty": cs.get("difficulty", ""),
                        "flags": cs.get("flags", 0), "facts": facts[:6]})
    recipes.sort(key=lambda r: r["code"])
    with kb_path.open("w", encoding="utf-8") as f:
        for r in recipes:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"seeded {len(recipes)} solved-case recipes -> {kb_path}")
    by_fam = {}
    for r in recipes:
        by_fam.setdefault(r["family"], []).append(r["code"])
    for fam in sorted(by_fam):
        print(f"  {fam}: {by_fam[fam]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "out"))

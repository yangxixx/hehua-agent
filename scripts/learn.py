#!/usr/bin/env python3
import json
import sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hehua.core.knowledge import family_of

def _notes_facts(nf: Path):
    facts, fails = ([], [])
    if not nf.exists():
        return (facts, fails)
    for line in nf.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get('kind') == 'fact':
            facts.append(e.get('content', ''))
        elif e.get('kind') == 'failure':
            fails.append(e.get('content', ''))
    return (facts, fails)

def main(run_dir: str, out_dir: str | None=None) -> int:
    run = Path(run_dir)
    state = json.loads((run / 'state' / 'state.json').read_text(encoding='utf-8'))
    learned = Path(out_dir) if out_dir else run / 'learned'
    learned.mkdir(parents=True, exist_ok=True)
    recipes, deadends_by_fam = ([], defaultdict(list))
    attempted = defaultdict(int)
    solved = defaultdict(int)
    for code, cs in state.items():
        fam = family_of(code)
        if cs.get('status') == 'solved':
            solved[fam] += 1
            attempted[fam] += 1
            facts, _ = _notes_facts(run / 'out' / code / 'notes.jsonl')
            if facts:
                recipes.append({'code': code, 'family': fam, 'difficulty': cs.get('difficulty', ''), 'flags': cs.get('flags', 0), 'facts': facts[:6]})
        elif cs.get('attempts', 0) > 0:
            attempted[fam] += 1
            _, fails = _notes_facts(run / 'out' / code / 'notes.jsonl')
            for f in fails[:4]:
                deadends_by_fam[fam].append({'code': code, 'failure': f[:200]})
    with (learned / 'knowledge.jsonl').open('w', encoding='utf-8') as f:
        for r in recipes:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    priors = {fam: round(solved[fam] / attempted[fam], 3) for fam in attempted if attempted[fam] > 0}
    (learned / 'priors.json').write_text(json.dumps(priors, ensure_ascii=False, indent=2), encoding='utf-8')
    with (learned / 'deadends.jsonl').open('w', encoding='utf-8') as f:
        for fam, items in deadends_by_fam.items():
            f.write(json.dumps({'family': fam, 'dead_ends': items[:6]}, ensure_ascii=False) + '\n')
    print(f'learned bundle -> {learned}')
    print(f'  knowledge.jsonl : {len(recipes)} solved-case recipes')
    print(f'  priors.json     : {priors}')
    print(f'  deadends.jsonl  : {sum((len(v) for v in deadends_by_fam.values()))} failure notes across {len(deadends_by_fam)} families')
    return 0
if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else 'out', sys.argv[2] if len(sys.argv) > 2 else None))

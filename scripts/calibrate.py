#!/usr/bin/env python3
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hehua.orchestrate.scheduler import PRIOR, prefix_of
MIN_ATTEMPTS = 3

def main() -> None:
    state_path = Path(sys.argv[1] if len(sys.argv) > 1 else 'state/state.json')
    out_path = Path(sys.argv[2] if len(sys.argv) > 2 else 'priors.json')
    st = json.loads(state_path.read_text(encoding='utf-8'))
    agg: dict[str, list[int, int]] = {}
    for s in st.values():
        if s.get('attempts', 0) < 1:
            continue
        pre = prefix_of(s['code'])
        a = agg.setdefault(pre, [0, 0])
        a[1] += 1
        if s.get('flags', 0) > 0:
            a[0] += 1
    out = {}
    for pre, (solved, tries) in agg.items():
        pub = PRIOR.get(pre, 0.5)
        if tries >= MIN_ATTEMPTS:
            out[pre] = round(0.5 * pub + 0.5 * solved / tries, 2)
        else:
            out[pre] = pub
    out_path.write_text(json.dumps(out, indent=1), encoding='utf-8')
    print(json.dumps(out))
if __name__ == '__main__':
    main()

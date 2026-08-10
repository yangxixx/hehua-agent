from __future__ import annotations
import json
from ..llm.client import LLMClient
_HV_MARKERS = ('noted [fact]', 'correct=true', 'correct = true')

def estimate_tokens(messages: list[dict]) -> int:
    total = 0
    for m in messages:
        total += len(json.dumps(m, ensure_ascii=False)) // 4
    return total

def compact(messages: list[dict], llm: LLMClient, prompt: str, notes=None, keep_tail: int=20) -> list[dict]:
    if len(messages) <= keep_tail + 2:
        return messages
    start = max(1, len(messages) - keep_tail)
    while start > 1 and messages[start]['role'] == 'tool':
        start -= 1
    head, middle, tail = (messages[:1], messages[1:start], messages[start:])

    def high_value(m: dict) -> bool:
        if m.get('role') != 'tool':
            return False
        c = str(m.get('content') or '').lower()
        return any((s in c for s in _HV_MARKERS))
    keep = set()
    for i, m in enumerate(middle):
        if high_value(m):
            keep.add(i)
            j = i - 1
            while j >= 0 and middle[j].get('role') != 'assistant':
                j -= 1
            if j >= 0:
                keep.add(j)
    for i in sorted(list(keep)):
        if middle[i].get('role') == 'assistant' and middle[i].get('tool_calls'):
            k = i + 1
            while k < len(middle) and middle[k].get('role') == 'tool':
                keep.add(k)
                k += 1
    if len(keep) > 16:
        keep = set(sorted(keep)[-16:])
    keep_mid = [m for i, m in enumerate(middle) if i in keep]
    comp_mid = [m for i, m in enumerate(middle) if i not in keep]
    transcript = '\n'.join((f"{m.get('role')}: {json.dumps(m.get('content') or m.get('tool_calls'), ensure_ascii=False)[:500]}" for m in comp_mid))
    if notes is not None:
        snap = notes.snapshot(40)
        if snap and snap != '(no notes yet)':
            transcript += '\n\n[durable notes so far — keep these exact facts]\n' + snap
    try:
        r = llm.chat([{'role': 'system', 'content': prompt}, {'role': 'user', 'content': transcript[:24000]}], model_role='compact', temperature=0.0)
        summary = r.content[:2000] or '(summary failed)'
    except Exception:
        summary = '(auto-dropped middle history)'
    return head + [{'role': 'user', 'content': f'[history summary]\n{summary}'}] + keep_mid + tail

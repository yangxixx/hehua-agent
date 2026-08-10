"""Context-window management: rough token estimate + fact-aware rolling summary."""
from __future__ import annotations

import json

from ..llm.client import LLMClient

# tool-result substrings that mark a high-value turn worth keeping verbatim
# (a correct flag submission, or a recorded fact) instead of lossy-summarizing.
_HV_MARKERS = ("noted [fact]", "correct=true", "correct = true")


def estimate_tokens(messages: list[dict]) -> int:
    total = 0
    for m in messages:
        total += len(json.dumps(m, ensure_ascii=False)) // 4
    return total


def compact(messages: list[dict], llm: LLMClient, prompt: str,
            notes=None, keep_tail: int = 20) -> list[dict]:
    """Summarize the middle of the conversation; keep system + recent tail.

    Fact-aware (#5): tool turns that produced a FACT or a CORRECT submit are
    kept VERBATIM (with their assistant tool_call parent) — raw exploit evidence
    (the nuclei hit, the RCE response, the flag) survives compaction, not just a
    lossy summary. Only the exploratory dead-ends in between get summarized.

    prior-run lesson (a-14 amnesia loop): the durable notes snapshot is force-fed
    to the summarizer AND re-anchored after compaction (see agent.py)."""
    if len(messages) <= keep_tail + 2:
        return messages
    # boundary alignment: a trailing tool message whose assistant tool_calls got
    # summarized away makes the whole conversation invalid (deepseek 400).
    start = max(1, len(messages) - keep_tail)
    while start > 1 and messages[start]["role"] == "tool":
        start -= 1
    head, middle, tail = messages[:1], messages[1:start], messages[start:]

    # --- fact-aware partition of the middle ---
    def high_value(m: dict) -> bool:
        if m.get("role") != "tool":
            return False
        c = str(m.get("content") or "").lower()
        return any(s in c for s in _HV_MARKERS)

    keep = set()
    for i, m in enumerate(middle):
        if high_value(m):
            keep.add(i)
            # parent assistant (nearest preceding) that issued this tool_call
            j = i - 1
            while j >= 0 and middle[j].get("role") != "assistant":
                j -= 1
            if j >= 0:
                keep.add(j)
    # keep a kept assistant's ENTIRE contiguous tool-result block (OpenAI needs
    # every tool_call id answered) + cap the kept set so it can't dominate
    for i in sorted(list(keep)):
        if middle[i].get("role") == "assistant" and middle[i].get("tool_calls"):
            k = i + 1
            while k < len(middle) and middle[k].get("role") == "tool":
                keep.add(k)
                k += 1
    if len(keep) > 16:                       # bound: keep only the most recent HV
        keep = set(sorted(keep)[-16:])

    keep_mid = [m for i, m in enumerate(middle) if i in keep]
    comp_mid = [m for i, m in enumerate(middle) if i not in keep]

    transcript = "\n".join(
        f"{m.get('role')}: {json.dumps(m.get('content') or m.get('tool_calls'), ensure_ascii=False)[:500]}"
        for m in comp_mid)
    if notes is not None:
        snap = notes.snapshot(40)
        if snap and snap != "(no notes yet)":
            transcript += "\n\n[durable notes so far — keep these exact facts]\n" + snap
    try:
        r = llm.chat(
            [{"role": "system", "content": prompt},
             {"role": "user", "content": transcript[:24000]}],
            model_role="compact", temperature=0.0)
        summary = r.content[:2000] or "(summary failed)"
    except Exception:  # noqa: BLE001 — never crash the solve loop on compaction
        summary = "(auto-dropped middle history)"
    return (head + [{"role": "user", "content": f"[history summary]\n{summary}"}]
            + keep_mid + tail)

"""Context-window management: rough token estimate + rolling summarization."""
from __future__ import annotations

import json

from ..llm.client import LLMClient


def estimate_tokens(messages: list[dict]) -> int:
    total = 0
    for m in messages:
        total += len(json.dumps(m, ensure_ascii=False)) // 4
    return total


def compact(messages: list[dict], llm: LLMClient, prompt: str,
            notes=None, keep_tail: int = 20) -> list[dict]:
    """Summarize the middle of the conversation; keep system + recent tail.

    run-6661 lesson (a-14 amnesia loop): the summary alone kept losing the
    list of already-tried paths, so every continuation re-fuzzed the same
    dead parameters. The durable notes snapshot is therefore force-fed to
    the summarizer AND re-anchored after compaction (see agent.py)."""
    if len(messages) <= keep_tail + 2:
        return messages
    # boundary alignment: a trailing tool message whose assistant tool_calls
    # got summarized away makes the whole conversation invalid (deepseek 400).
    # extend the tail backwards until it starts on a non-tool message.
    start = max(1, len(messages) - keep_tail)
    while start > 1 and messages[start]["role"] == "tool":
        start -= 1
    head, middle, tail = messages[:1], messages[1:start], messages[start:]
    transcript = "\n".join(
        f"{m.get('role')}: {json.dumps(m.get('content') or m.get('tool_calls'), ensure_ascii=False)[:500]}"
        for m in middle)
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
    return head + [{"role": "user",
                    "content": f"[history summary]\n{summary}"}] + tail

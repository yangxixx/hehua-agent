"""Context compaction must keep tool blocks aligned (no orphan tool msgs)."""
from hehua.core import context as ctxmod
from hehua.llm.client import ChatResult


class FakeLLM:
    def chat(self, messages, tools=None, model_role="primary", temperature=0.0):
        return ChatResult(content="summary", model="fake")


def _conv(n_blocks=30):
    msgs = [{"role": "system", "content": "sys"},
            {"role": "user", "content": "go"}]
    for i in range(n_blocks):
        msgs.append({"role": "assistant", "content": "",
                     "tool_calls": [{"id": f"c{i}", "type": "function",
                                     "function": {"name": "bash", "arguments": "{}"}}]})
        msgs.append({"role": "tool", "tool_call_id": f"c{i}", "content": f"out{i}"})
    return msgs


def test_compact_keeps_tool_blocks_aligned():
    out = ctxmod.compact(_conv(), FakeLLM(), "summarize", keep_tail=7)
    # invariant: every tool msg has a preceding assistant tool_calls in-list
    ids = set()
    for m in out:
        if m.get("tool_calls"):
            ids.update(tc["id"] for tc in m["tool_calls"])
        if m["role"] == "tool":
            assert m["tool_call_id"] in ids, "orphan tool message after compact"
    assert out[1]["role"] == "user" and "summary" in out[1]["content"]


def test_compact_short_conversation_untouched():
    msgs = _conv(2)
    assert ctxmod.compact(msgs, FakeLLM(), "s", keep_tail=20) is msgs

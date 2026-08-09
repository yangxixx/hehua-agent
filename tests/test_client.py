"""LLM client: parsing, retry, failover, context overflow — against a fake endpoint."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hehua.llm.budget import Budget
from hehua.llm.client import ContextOverflow, LLMClient, LLMUnavailable
from hehua.llm.registry import Provider


def _openai_body(model="fake-model", tool_call=None):
    msg = {"role": "assistant", "content": "ok"}
    if tool_call:
        msg["tool_calls"] = [{
            "id": "c1", "type": "function",
            "function": {"name": tool_call[0],
                         "arguments": json.dumps(tool_call[1])},
        }]
    return {
        "choices": [{"message": msg}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        "model": model,
    }


class ScriptedHandler(BaseHTTPRequestHandler):
    """Behavior scripted via server.script: list of (status, body_dict|None)."""

    def do_POST(self):
        self.server.hits = getattr(self.server, "hits", 0) + 1
        status, body = self.server.script.pop(0) \
            if self.server.script else (200, _openai_body())
        payload = json.dumps(body or {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr("hehua.llm.client.LLMClient._backoff",
                        staticmethod(lambda attempt: None))


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ScriptedHandler)
    srv.script = []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def _base(srv):
    return f"http://127.0.0.1:{srv.server_address[1]}/v1"


def test_tool_call_parsing_and_usage(server):
    server.script = [(200, _openai_body(tool_call=("bash", {"command": "id"})))]
    c = LLMClient([Provider("p", _base(server), "k", "m")], Budget())
    r = c.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function"}])
    assert r.tool_calls[0].name == "bash"
    assert r.tool_calls[0].arguments == {"command": "id"}
    assert r.usage["prompt_tokens"] == 10
    assert c.budget.totals()["total_tokens"] == 15


def test_retry_on_5xx_then_success(server):
    server.script = [(500, {"err": 1}), (503, {"err": 1}), (200, _openai_body())]
    c = LLMClient([Provider("p", _base(server), "k", "m")])
    r = c.chat([{"role": "user", "content": "hi"}])
    assert r.content == "ok"
    assert server.hits == 3


def test_context_overflow_raised(server):
    server.script = [(400, {"error": "maximum context length exceeded"})]
    c = LLMClient([Provider("p", _base(server), "k", "m")])
    with pytest.raises(ContextOverflow):
        c.chat([{"role": "user", "content": "x"}])


def test_failover_to_second_provider():
    bad = ThreadingHTTPServer(("127.0.0.1", 0), ScriptedHandler)
    bad.script = [(401, {"e": 1}), (401, {"e": 1}), (401, {"e": 1})]
    good = ThreadingHTTPServer(("127.0.0.1", 0), ScriptedHandler)
    good.script = [(200, _openai_body(model="backup"))]
    for s in (bad, good):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        c = LLMClient([Provider("a", _base(bad), "k", "m"),
                       Provider("b", _base(good), "k", "backup")])
        r = c.chat([{"role": "user", "content": "hi"}])
        assert r.model == "backup"
    finally:
        bad.shutdown()
        good.shutdown()


def test_no_providers_raises():
    c = LLMClient([Provider("a", "http://x", "", "m")])  # empty key -> filtered
    with pytest.raises(LLMUnavailable):
        c.chat([{"role": "user", "content": "hi"}])

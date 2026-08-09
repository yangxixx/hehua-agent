"""Watchdog: repetition + no-progress injections."""
from hehua.config import Config
from hehua.core.agent import Watchdog


def test_repeat_command_injection():
    w = Watchdog(Config())
    out = []
    for _ in range(3):
        out += w.observe("bash", {"command": "curl -s http://x/"}, progress=False)
    assert any("SAME command" in i for i in out)


def test_no_progress_injection():
    w = Watchdog(Config())
    out = []
    for i in range(8):
        out += w.observe("http_request", {"url": f"http://x/{i}"}, progress=False)
    assert any("No progress" in i for i in out)


def test_progress_resets_counter():
    w = Watchdog(Config())
    for i in range(7):
        w.observe("bash", {"command": f"cmd{i}"}, progress=False)
    w.observe("notes", {"kind": "fact"}, progress=True)
    out = []
    for i in range(7):
        out += w.observe("bash", {"command": f"other{i}"}, progress=False)
    assert not any("No progress" in i for i in out)

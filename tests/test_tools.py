"""Tools: round-trips, truncation, bash timeout kill."""
import sys
import time
from pathlib import Path

from hehua.config import Config
from hehua.core.memory import Notes
from hehua.core.tools import ToolContext, build_tools, cap


def _ctx(tmp_path: Path) -> ToolContext:
    return ToolContext(workdir=tmp_path, notes=Notes(), submit_fn=lambda f, w="":
                       {"correct": True, "remaining": 0, "awarded": 100})


def test_write_read_roundtrip(tmp_path):
    t = build_tools(_ctx(tmp_path), Config())
    t["write_file"](path="x.txt", content="hello\nworld")
    assert "hello" in t["read_file"](path="x.txt")


def test_cap_truncation():
    s = "a" * 20000
    out = cap(s, 8192)
    assert len(out) < 20000 and "truncated" in out


def test_bash_timeout_kill(tmp_path):
    t = build_tools(_ctx(tmp_path), Config())
    start = time.time()
    r = t["bash"](command=f'{sys.executable} -c "import time;time.sleep(9)"',
                  timeout=1)
    assert time.time() - start < 8
    assert "timeout" in r or "exit=-1" in r


def test_bash_output_spooled(tmp_path):
    t = build_tools(_ctx(tmp_path), Config())
    r = t["bash"](command=f'{sys.executable} -c "print(\'A\'*20000)"')
    assert "truncated" in r or "full log" in r
    assert (tmp_path / "out").exists()


def test_submit_remaining_hint(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.submit_fn = lambda f, w="": {"correct": True, "remaining": 1, "awarded": 50}
    t = build_tools(ctx, Config())
    assert "more flag" in t["submit_flag"](flag="flag{x}")


def test_wrong_flag_dedupe(tmp_path):
    calls = []

    def fake(flag, w=""):
        calls.append(flag)
        return {"correct": False, "remaining": 1, "awarded": 0}

    ctx = ToolContext(workdir=tmp_path, notes=Notes(), submit_fn=fake)
    t = build_tools(ctx, Config())
    assert "incorrect" in t["submit_flag"](flag="flag{decoy}")
    out = t["submit_flag"](flag="flag{decoy}")
    assert "WRONG" in out and len(calls) == 1  # second submit blocked locally


def test_notes_kinds(tmp_path):
    n = Notes()
    n.add("fact", "port 80 open")
    n.add("bogus", "x")  # coerced to fact
    assert n.facts_count() == 2
    assert "[fact]" in n.snapshot()


def test_finish_early_giveup_rejected(tmp_path):
    """run-6661 c-04: instant give-up with zero facts must be blocked."""
    ctx = _ctx(tmp_path)
    t = build_tools(ctx, Config())
    out = t["finish"](summary="nothing responds", give_up=True)
    assert "REJECTED" in out and not ctx.finished


def test_finish_giveup_ok_with_facts(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.notes.add("fact", "port 9004 open, HTTP 503 on all paths")
    t = build_tools(ctx, Config())
    out = t["finish"](summary="target broken", give_up=True)
    assert ctx.finished and ctx.gave_up and "REJECTED" not in out


def test_finish_success_never_blocked(tmp_path):
    ctx = _ctx(tmp_path)
    t = build_tools(ctx, Config())
    t["finish"](summary="solved via sqli", give_up=False)
    assert ctx.finished and not ctx.gave_up


def test_finish_giveup_ok_after_5min(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.start_ts = time.time() - 301
    t = build_tools(ctx, Config())
    t["finish"](summary="dead end", give_up=True)
    assert ctx.finished and ctx.gave_up

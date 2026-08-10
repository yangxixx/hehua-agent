"""Tests for the finish-gate (#12) and port_scan tool (#11)."""
from hehua.core.tools import ToolContext, build_schemas, build_tools
from hehua.core.memory import Notes


def _ctx(tmp_path):
    return ToolContext(workdir=tmp_path, notes=Notes(tmp_path / "n.jsonl"),
                       submit_fn=lambda f, w="": {"correct": False, "remaining": 1})


def test_finish_gate_blocks_when_flags_remain(tmp_path):
    cfg = type("C", (), {"bash_timeout": 120, "bash_timeout_max": 300,
                         "head_tail": 4096})()
    ctx = _ctx(tmp_path)
    tools = build_tools(ctx, cfg)
    # simulate a correct submit that left more flags on the challenge
    ctx.last_submit = {"correct": True, "remaining": 2}
    out = tools["finish"](summary="done")
    assert "FINISH GATE" in out and not ctx.finished   # blocked, one verify pass
    out2 = tools["finish"](summary="done")             # second call proceeds
    assert ctx.finished


def test_finish_gate_skipped_when_no_remaining(tmp_path):
    cfg = type("C", (), {"bash_timeout": 120, "bash_timeout_max": 300,
                         "head_tail": 4096})()
    ctx = _ctx(tmp_path)
    tools = build_tools(ctx, cfg)
    ctx.last_submit = {"correct": True, "remaining": 0}
    tools["finish"](summary="done")
    assert ctx.finished                                  # no gate, finishes


def test_port_scan_in_schemas():
    names = {t["function"]["name"] for t in build_schemas()}
    assert "port_scan" in names and "finish" in names

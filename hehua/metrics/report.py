"""Generate the BSRC-facing metrics report (量化指标 vs 传统模式)."""
from __future__ import annotations

import json
from pathlib import Path

from ..orchestrate.state import SOLVED, State


def generate(state: State, budget_totals: dict, events_path: str | Path,
             out_path: str | Path = "reports/report.md") -> str:
    events = []
    ep = Path(events_path)
    if ep.exists():
        for line in ep.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    states = list(state.challenges.values())
    n = len(states) or 1
    solved = [s for s in states if s.status == SOLVED]
    partial = [s for s in states if s.status == "partial"]
    flags = sum(s.flags for s in states)
    flag_total = sum(s.flag_count for s in states) or 1
    elapsed_total = sum(s.elapsed for s in states)
    submits = [e for e in events if e["type"] == "submit"]
    correct_submits = [e for e in submits if e.get("correct")]
    precision = (len(correct_submits) / len(submits)) if submits else 0.0
    llm_calls = [e for e in events if e["type"] == "llm_call"]

    lines = [
        "# Hehua 评测报告",
        "",
        "## 总览",
        f"- 题目数: {len(states)}　已解: {len(solved)}　部分: {len(partial)}",
        f"- flag 发现率: {flags}/{flag_total} = {flags / flag_total:.1%}",
        f"- 提交精度(1-误报率代理): {precision:.1%} "
        f"({len(correct_submits)}/{len(submits)})",
        f"- 总解题耗时: {elapsed_total / 60:.1f} min　单题均时: "
        f"{elapsed_total / n / 60:.1f} min",
        f"- LLM 调用次数: {len(llm_calls)}",
        f"- Token 消耗: {budget_totals.get('total_tokens', 0):,} "
        f"(prompt {budget_totals.get('prompt_tokens', 0):,} / "
        f"completion {budget_totals.get('completion_tokens', 0):,})",
        "",
        "## 按难度",
    ]
    by_diff: dict[str, list] = {}
    for s in states:
        by_diff.setdefault(getattr(s, "difficulty", "unknown"), []).append(s)
    for d, ss in sorted(by_diff.items()):
        sv = sum(1 for s in ss if s.status == SOLVED)
        lines.append(f"- {d}: {sv}/{len(ss)} solved")
    lines += ["", "## 单题明细", "| code | status | flags | attempts | elapsed(s) |",
              "|---|---|---|---|---|"]
    for s in states:
        lines.append(f"| {s.code} | {s.status} | {s.flags}/{s.flag_count} | "
                     f"{s.attempts} | {s.elapsed:.0f} |")
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(out)

#!/usr/bin/env python3
"""Summarize the live run from logs/events.jsonl for monitoring."""
import json
import sys
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "logs/events.jsonl"
events = []
for line in open(path, encoding="utf-8"):
    line = line.strip()
    if line:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass

# scope to the CURRENT run: keep only events from the last run_start onward
last_start = -1
for i, e in enumerate(events):
    if e.get("type") == "run_start":
        last_start = i
if last_start >= 0:
    events = events[last_start:]

solved, failed, partial = set(), set(), set()
flags_correct = 0
submits = 0
wrong = 0
starts = defaultdict(int)
cur_active = set()
errors = []
tokens = 0
llm_calls = 0
last_ts = ""
for e in events:
    t = e.get("type")
    last_ts = e.get("ts", last_ts)
    if t == "challenge_end":
        code = e.get("code")
        st = e.get("status")
        if st == "solved":
            solved.add(code)
        elif st == "partial":
            partial.add(code)
        else:
            failed.add(code)
    elif t == "challenge_start":
        starts[e.get("code")] += 1
    elif t == "submit":
        submits += 1
        if e.get("correct"):
            flags_correct += 1
        else:
            wrong += 1
    elif t == "llm_call":
        llm_calls += 1
        tokens += (e.get("usage") or {}).get("total_tokens", 0)
    elif t in ("solve_error", "worker_error", "task_ended", "prescan_error"):
        errors.append(e)

escalated = [e.get("code") for e in events if e.get("type") == "escalated"]
glm_starts = [e.get("code") for e in events
              if e.get("type") == "challenge_start" and e.get("phase") == "GLM"]
glm_solved = [e.get("code") for e in events
              if e.get("type") == "challenge_end" and e.get("status") == "solved"
              and e.get("code") in set(glm_starts)]
print(f"last event ts : {last_ts}")
print(f"solved   : {len(solved)}")
print(f"partial  : {len(partial)}  {sorted(partial)[:8]}")
print(f"failed   : {len(failed)}")
print(f"flags    : {flags_correct} correct / {submits} submits ({wrong} wrong)")
print(f"attempts : {sum(starts.values())} starts across {len(starts)} challenges")
print(f"escalated: {len(escalated)} to GLM | GLM attempts: {len(glm_starts)} | GLM solved: {len(set(glm_solved))} {sorted(set(glm_solved))[:6]}")
print(f"llm calls: {llm_calls}   tokens: {tokens:,}")
if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors[-6:]:
        print("   ", e.get("type"), str(e)[:140])

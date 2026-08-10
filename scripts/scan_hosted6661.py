#!/usr/bin/env python3
"""Map our hosted run 6661 sessions to challenges + outcomes (v2 image)."""
import json
import re
import sys
import urllib.request

BASE = "https://tsecbench.zc.tencent.com/api/v1/leaderboard/agent/6661/llm"
AUTH = ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjAzIiwiZXhwIjoxNzg2Mjg2ODc3fQ."
        "ikZ525fmNIwpcX3YnV06T5JTYl7-WdZKH31vZQ4OmP8")
FROM = "2026-08-08T04:25:00Z"
TO = "2026-08-08T08:30:00Z"


def get(url):
    req = urllib.request.Request(url, headers={"Authorization": AUTH})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)


sess = json.load(open("sess6661.json", encoding="utf-8"))
print("sessions:", len(sess), file=sys.stderr)

rows = []
full = {}
for i, s in enumerate(sess):
    sid = s["session_id"]
    steps = []
    page = 1
    while page <= 12:
        try:
            d = get(f"{BASE}/sessions/{sid}?from={FROM}&to={TO}"
                    f"&page={page}&page_size=50")
        except Exception as e:
            print(sid, "ERR", e, file=sys.stderr)
            break
        st = d.get("steps") or []
        if not st:
            break
        steps += st
        page += 1
    code = ""
    give_up = None
    last_think = ""
    finish_summary = ""
    n_tools = 0
    tool_seq = []
    submits = []
    for stx in steps:
        for it in stx.get("items", []):
            k = it.get("kind")
            t = (it.get("text") or "")
            if not code and "Challenge: " in t:
                m = re.search(r"Challenge: ([a-z0-9-]+)", t)
                if m:
                    code = m.group(1)
            if k == "tool_call":
                n_tools += 1
                nm = it.get("name") or ""
                tool_seq.append(nm)
                if nm == "finish":
                    try:
                        a = json.loads(t) if t else (it.get("args") or {})
                    except Exception:
                        a = {}
                    if isinstance(a, dict):
                        give_up = a.get("give_up")
                        finish_summary = (a.get("summary") or "")[:500]
                if nm == "submit_flag":
                    submits.append(t[:200])
            if k == "thinking":
                last_think = t[:600]
    rows.append({"sid": sid, "code": code, "tools": n_tools,
                 "give_up": give_up, "summary": finish_summary,
                 "think": last_think, "tool_seq": tool_seq,
                 "submits": submits,
                 "first": s.get("first_captured_at"),
                 "last": s.get("last_active_at"),
                 "events": s.get("event_count")})
    full[sid] = steps
    if (i + 1) % 10 == 0:
        print(f"{i+1}/{len(sess)} done", file=sys.stderr)

json.dump(rows, open("hosted_sessions6661.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
json.dump(full, open("sess6661_full.json", "w", encoding="utf-8"),
          ensure_ascii=False)
for r in sorted(rows, key=lambda x: x["code"] or "~"):
    print(r["code"] or "?", r["sid"], "tools", r["tools"],
          "give_up", r["give_up"], (r["summary"] or "")[:60])

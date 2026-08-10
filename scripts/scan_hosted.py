#!/usr/bin/env python3
"""Map our hosted run 6639 sessions to challenges + outcomes."""
import json
import re
import sys
import urllib.request

BASE = "https://tsecbench.zc.tencent.com/api/v1/leaderboard/agent/6639/llm"
AUTH = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjAzIiwiZXhwIjoxNzg2MTg3MjE4fQ.tfSVW-xK9QhY0ooaUpbWi8ynuG9nxjjAt5sMCfieO_k"
FROM = "2026-08-07T18:38:51Z"
TO = "2026-08-07T22:53:31Z"


def get(url):
    req = urllib.request.Request(url, headers={"Authorization": AUTH})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)


sess = get(f"{BASE}/sessions?from={FROM}&to={TO}&page=1&page_size=100")["items"]
if len(sess) >= 100:
    sess += get(f"{BASE}/sessions?from={FROM}&to={TO}&page=2&page_size=100")["items"]
print("sessions:", len(sess), file=sys.stderr)

rows = []
for s in sess:
    sid = s["session_id"]
    steps = []
    page = 1
    while page <= 10:
        try:
            d = get(f"{BASE}/sessions/{sid}?from={FROM}&to={TO}&page={page}&page_size=50")
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
                if it.get("name") == "finish":
                    try:
                        a = json.loads(t) if t else (it.get("args") or {})
                    except Exception:
                        a = {}
                    if isinstance(a, dict):
                        give_up = a.get("give_up")
                        finish_summary = (a.get("summary") or "")[:300]
            if k == "thinking":
                last_think = t[:400]
    rows.append({"sid": sid, "code": code, "tools": n_tools,
                 "give_up": give_up, "summary": finish_summary,
                 "think": last_think})

json.dump(rows, open("hosted_sessions.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
for r in sorted(rows, key=lambda x: x["code"]):
    print(r["code"] or "?", r["sid"], "tools", r["tools"], "give_up", r["give_up"])

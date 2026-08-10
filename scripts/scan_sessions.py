#!/usr/bin/env python3
"""Map ez-claude (run 5739) LLM sessions to c-series challenges by markers."""
import json
import re
import sys
import urllib.request

BASE = "https://tsecbench.zc.tencent.com/api/v1/leaderboard/agent/5739/llm"
FROM = "2026-07-31T15:00:00Z"
TO = "2026-08-01T00:00:00Z"

MARKERS = {
    "hugegraph": r"hugegraph|gremlin",
    "geoserver": r"geoserver|36401|ogc|wfs",
    "jdwp": r"jdwp|5005",
    "gradio": r"gradio|7860",
    "comfyui": r"comfyui|8188",
    "1panel": r"1panel|10086",
    "ssh-rlogin": r"ssh|2222|paramiko",
}

sess = json.load(open("sess.json", encoding="utf-8"))["items"]


def fetch(sid):
    url = f"{BASE}/sessions/{sid}?from={FROM}&to={TO}"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


hits = {}
for s in sess:
    sid = s["session_id"]
    if s["event_count"] < 10:
        continue
    try:
        d = fetch(sid)
    except Exception as e:
        print(sid, "ERR", e, file=sys.stderr)
        continue
    blob = []
    for st in d.get("steps", []):
        for it in st.get("items", []):
            t = it.get("text") or ""
            if t:
                blob.append(t[:2000])
    text = "\n".join(blob)
    found = [name for name, rx in MARKERS.items() if re.search(rx, text, re.I)]
    if found:
        hits[sid] = found
        print(sid, s["first_captured_at"][11:16], s["event_count"], found,
              s.get("title", "")[:40].replace("\n", " "))

json.dump(hits, open("session_map.json", "w"), indent=1)
print("TOTAL", len(hits))

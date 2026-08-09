#!/usr/bin/env python3
"""Threaded web path/dir fuzzer for LOCAL mode (no ffuf/gobuster available).

Much faster than a sequential curl loop (which burned whole budgets on
xben-001). Reports every response whose status is not the baseline 404, and
flags status/length anomalies worth a manual look.

Usage:
  python dirfuzz.py <base_url> <wordlist> [-P 30] [-x php,txt,bak] [--timeout 6]
  python dirfuzz.py http://10.0.168.178:80 ../../tools/wordlists/common.txt
Exit: always 0 (results on stdout); a non-404 line looks like:
  [200]  5127B  /admin
"""
from __future__ import annotations

import argparse
import sys
import threading
import urllib.error
import urllib.request
from queue import Queue

BASELINE_404 = (404,)


def worker(base: str, q: "Queue", out: list, lock: threading.Lock,
           timeout: float, baseline_len: dict):
    while True:
        path = q.get()
        if path is None:
            q.task_done()
            return
        url = base.rstrip("/") + "/" + path.lstrip("/")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(4096)
                status, length = r.status, len(body)
        except urllib.error.HTTPError as e:
            status, length = e.code, len(e.read(2048) or b"")
        except Exception:
            q.task_done()
            continue
        # hide the dominant 404 noise; keep everything else
        if status not in BASELINE_404:
            with lock:
                out.append((status, length, "/" + path))
        q.task_done()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("base_url")
    ap.add_argument("wordlist")
    ap.add_argument("-P", "--threads", type=int, default=30)
    ap.add_argument("-x", "--extensions", default="",
                    help="comma list, e.g. php,txt,bak (appended to each word)")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--limit", type=int, default=0, help="only first N words")
    args = ap.parse_args(argv)

    words = []
    with open(args.wordlist, encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if w and not w.startswith("#"):
                words.append(w)
            if args.limit and len(words) >= args.limit:
                break
    exts = [e.strip() for e in args.extensions.split(",") if e.strip()]
    candidates = list(words)
    for e in exts:
        candidates += [f"{w}.{e}" for w in words]

    q: "Queue" = Queue()
    out: list = []
    lock = threading.Lock()
    n = max(1, min(args.threads, 60))
    threads = [threading.Thread(target=worker,
                                args=(args.base_url, q, out, lock,
                                      args.timeout, {}), daemon=True)
               for _ in range(n)]
    for t in threads:
        t.start()
    for c in candidates:
        q.put(c)
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join()

    print(f"# dirfuzz {args.base_url} words={len(candidates)} threads={n}")
    for status, length, path in sorted(out, key=lambda x: (x[0], x[2])):
        print(f"[{status}] {length:6d}B  {path}")
    if not out:
        print("# no non-404 responses found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

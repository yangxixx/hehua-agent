# Evasion playbook (weight 10% — baseline)

1. Detect the filter: send probes, diff responses (WAF page vs 404 vs 200).
2. Encoding ladders: URL-encode, double-encode, unicode, case-mix, comment
   injection (`un/**/ion`), whitespace alternatives (`/**/`, `+`, `%09`).
3. SQLi under WAF: hex/char() concat, information_schema alternatives,
   error-based with odd functions, http-parameter-pollution.
4. CMDi under WAF: `${IFS}`, `$(echo a|base64 -d)`, concat `c''at`, env vars,
   `X=`ping`` tricks.
5. XSS under WAF: event handlers without tags, svg/animate, onerror variants,
   jsfuck as last resort.
6. Never brute the same blocked payload — mutate systematically; log what the
   filter blocks as facts to converge on its regex.

7. Field notes (live-calibrated 2026-08-07, nginx + ModSecurity-CRS-like WAF):
   - single tokens (' -- OR UNION SELECT =) pass; 403 fires on COMBINATION
     patterns (tautologies: OR/LIKE/IN/=/substr/length/mid; quote+comment).
   - keyword doubling (OORR) evades detection but the WAF does NOT strip, so
     the backend receives the doubled text verbatim ⇒ doubling only works
     against STRIPPING WAFs (custom-filter challenges, "自定义过滤规则").
   - multipart / charset=utf-16 / HPP did NOT bypass.
   - when tautologies 403, switch primitive: injection in the PASSWORD field,
     backslash truncation (`admin\`), header-carried payloads (User-Agent /
     Cookie / Referer) if backend uses them, ORDER BY / numeric probes, or
     non-keyword booleans; always diff responses to map the rule set first.
8b. EVASION CODING templates (detector flags API NAMES & imports):
   - NO string literals: build names on stack from char math at runtime.
   - Resolve APIs yourself: walk PEB→Ldr→InMemoryOrder, hash each export
     (ror13 add hash), compare hashes; call via function pointer.
   - Prefer indirect syscalls: allocate with VirtualAlloc resolved as above or
     raw syscall numbers via `syscall` instruction stub (no ntdll import).
   - Keep structure REAL (functions+imports+assignments pass precheck) but
     imports only kernel32!GetModuleHandleA-level benign set; do the rest via
     resolved pointers. Iterate against the returned bypass score (oracle).

8. Detection-evasion CODING challenges (submit code, get a bypass score):
   the returned score is an ORACLE — hill-climb it: script a loop of
   submit→read score→mutate (indirect syscalls, API-name hashing, drop
   literal strings like "VirtualAlloc", swap CreateRemoteThread for
   NtCreateSection/section-mapping, early-bird APC). Never hand-submit once
   and quit; 5 rules × feedback = solvable by iteration.
   MANDATORY PATTERN: write ONE python script that holds a variant table and
   loops submit→parse score→try next variant automatically (20+ variants per
   run), printing a score ladder; run it via bash and read the ladder.
   Hand-crafting one submission per tool call is FORBIDDEN on oracle tasks.

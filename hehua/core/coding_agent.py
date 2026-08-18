"""Coding-agent solve loop: continuous tool-use, NOTES_{model}.md memory.

One unbroken chain-of-thought per target per model — LLM thinks →
bash/http/exploit → observe → repeat → report findings. Memory = plain files
the agents read/write. Zero orchestration overhead.

Supports parallel multi-model: several coding agents work the same target,
each with a PRIVATE notes file (no anchoring), a SHARED raw layer
(TRANSCRIPT/scripts/INFRA/RECON) and a ~2min cross-read sync nudge.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..llm.client import QuotaExhausted
from . import context as ctxmod
from .agent import PROMPTS_DIR, _wait_targets_ready, pick_playbook
from .memory import Notes
from .tools import ToolContext, build_schemas, build_tools


@dataclass
class CodingOutcome:
    finished: bool
    gave_up: bool
    steps: int
    elapsed: float
    model: str
    # every bash process-group the session spawned (proxies/tunnels/scans —
    # incl. `cmd &` stragglers). The runner kills them all at run end so
    # half-built infra dies with the session.
    pgids: list = field(default_factory=list)


# Attack-class lenses: parallel models each take a DIFFERENT lens so they
# don't converge on the same dead end; re-runs rotate lenses the same way.
_ATTEMPT_FOCUS = [
    "auth/session/JWT/cookie manipulation, privilege escalation via tokens",
    "blind/OOB injection (time/DNS/OOB exfiltration), unusual parameters & headers",
    "business-logic abuse: race conditions, negative/overflow values, workflow skips",
    "source/dependency audit: read all routes & JS chunks, find forgotten endpoints",
    "crypto/misc: weak secrets, default creds, debug endpoints, backup files",
]


def _assistant_msg(res) -> dict:
    m: dict = {"role": "assistant", "content": res.content}
    if res.tool_calls:
        m["tool_calls"] = [{"id": c.id, "type": "function",
                            "function": {"name": c.name,
                                         "arguments": json.dumps(
                                             c.arguments, ensure_ascii=False)}}
                           for c in res.tool_calls]
    return m


def solve_coding(ch: dict, addrs: list, cfg: Config, llm, submit_fn, events,
                 workdir: Path, budget_min: float = 20.0,
                 model_name: str = "flash", stop_event=None,
                 notes_lock=None, send_thinking: bool = True,
                 system_name: str = "system_pentest.md",
                 attempt: int = 1, lens: str = "") -> CodingOutcome:
    """One continuous coding-agent session for one target with one model.

    No orchestration — just think→tool→observe→repeat.
    Writes findings to a PRIVATE NOTES_{model}.md (parallel models stay
    independent, cross-reading siblings every ~2min).
    Ends on finish, stop_event, or budget.

    attempt: 1 = first session on this target; 2+ = re-run on a target with
    prior work (drives the strategy-reset framing and the anti-repetition
    ledger so re-runs don't repeat themselves).
    lens: suggested attack-class focus for THIS model (parallel models get
    different lenses so they spread instead of duplicating work).
    """
    code = ch.get("unique_code", "")
    system = (PROMPTS_DIR / system_name).read_text(encoding="utf-8")
    # evidence-driven routing: description + accumulated notes intel (re-runs
    # re-route — first-pass recon can overturn a generic description)
    prior_notes = ""
    try:
        _pn = [p.read_text(encoding="utf-8")[:2000]
               for p in sorted(workdir.glob("NOTES_*.md"))]
        if not _pn and (workdir / "NOTES.md").exists():
            _pn = [(workdir / "NOTES.md").read_text(encoding="utf-8")[:4000]]
        prior_notes = "\n".join(_pn)[:4000]
    except OSError:
        pass
    pb = pick_playbook(ch.get("description", ""), code, prior_notes=prior_notes)
    system += "\n\n---\n" + (PROMPTS_DIR / pb).read_text(encoding="utf-8")
    # full knowledge index: the preloaded playbook is only the router's best
    # guess — the MODEL may load any other when evidence says so
    system += (
        "\n\n---\n🎯 DESCRIPTION = THE BIGGEST HINT — before ANY recon, map the "
        "target wording to a vuln class and attack THAT hypothesis first "
        "(agents routinely burn hundreds of commands discovering by trial "
        "what the description already stated):\n"
        "- 服务端渲染/模板预览/自定义主题/个人签名展示 → SSTI: engine "
        "fingerprint FIRST ({{7*7}}, ${7*7}, <%=7*7%>), then the matched "
        "engine's RCE chain\n"
        "- 不在互联网上/内网/隔离层/'借它去读' → SSRF chain: find the fetch "
        "point, then internal services/metadata/file://\n"
        "- 大模型/AI 助手/自动总结/导入 URL → LLM attacks: prompt injection + "
        "doc-import SSRF (the summarizer IS your exfil channel)\n"
        "- 多租户/数据隔离/互不可见 → isolation lives in the POLICY/rewrite "
        "layer, NOT the engine: qualified names, comment-split SQL, CTE nesting\n"
        "- 智能合约/链上逻辑 → blockchain: get the ABI/bytecode, audit "
        "on-chain logic\n"
        "- '照搬公开 payload 无效'/统一过滤/WAF → go STRAIGHT to the "
        "deformation matrix (inline comments, double-encoding, header/param "
        "relocation); never fire raw public payloads\n"
        '- "真实攻防演练"/懒得写 index/裸服务 → known-CVE/actuator check '
        "(fingerprint → hot-CVE table)\n"
        "- 检测运行环境/可信设备/风控 → client-side trust: the check is "
        "forgeable, replay the protocol\n"
        "- 看不见的字符/公告/正常文章但文件偏大 → steganography (zero-width, "
        "whitespace, trailing data)\n"
        "- 目录服务/密钥托管/SSO 集成 → LDAP injection + auth-method abuse\n"
        "Rank your top-2 hypotheses from the wording, note them, then verify "
        "the cheapest one first.\n"
        "\n---\n📚 KNOWLEDGE INDEX — other playbooks available (the one above "
        "is a first-guess; if your recon shows this target fits a different "
        "class, read_file the right one and follow it):\n"
        f"- {PROMPTS_DIR / 'playbook_web.md'} — web vulns, SSTI/SQLi/SSRF/"
        "auth/business-logic, hot-CVE quick table\n"
        f"- {PROMPTS_DIR / 'playbook_ai.md'} — LLM/agent attacks, prompt "
        "injection, MCP poisoning, doc-import SSRF\n"
        f"- {PROMPTS_DIR / 'playbook_binary.md'} — pwn/reversing, mobile "
        "protocol replay\n"
        f"- {PROMPTS_DIR / 'playbook_blockchain.md'} — smart-contract auditing\n"
        f"- {PROMPTS_DIR / 'playbook_cloud.md'} — cloud/metadata/container\n"
        f"- {PROMPTS_DIR / 'playbook_evasion.md'} — WAF/EDR evasion\n"
        f"- {PROMPTS_DIR / 'playbook_exploit.md'} — known-CVE exploitation "
        "recipes, fingerprint cheat-sheet\n"
        f"- {PROMPTS_DIR / 'playbook_killchain.md'} — internal-network "
        "killchain, pivoting\n")
    if pb in ("playbook_killchain.md", "playbook_exploit.md"):
        try:
            system += "\n\n---\n" + (PROMPTS_DIR / "poc_inventory.md").read_text(
                encoding="utf-8")
        except OSError:
            pass

    # notes tool → PRIVATE per-model notes file. Thinking stays independent
    # (no anchoring on siblings' early conclusions); the RAW layer
    # (TRANSCRIPT/scripts/INFRA/RECON) remains shared so work isn't duplicated.
    # Siblings cross-read NOTES_* on the ~2min sync nudge below.
    my_notes = workdir / f"NOTES_{model_name}.md"

    def notes_sink(kind, content):
        # provenance tag: which model, when — parallel models' conclusions
        # DO diverge (different paths, different target states over time);
        # readers need to know who concluded what under which conditions
        line = f"[{kind}|{model_name}|{time.strftime('%H:%M')}] {content}"
        try:
            if notes_lock:
                with notes_lock:
                    with open(my_notes, "a", encoding="utf-8") as f:
                        f.write(line + "\n")
            else:
                with open(my_notes, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except OSError:
            pass
        return f"noted [{kind}] {str(content)[:100]}"

    tctx = ToolContext(workdir=workdir, notes=Notes(), submit_fn=submit_fn,
                       addrs=addrs, notes_sink=notes_sink)
    tools = build_tools(tctx, cfg)
    schemas = build_schemas()

    # ---- multi-layer file memory ----
    notes_path = workdir / "NOTES.md"
    state_path = workdir / "STATE.md"
    transcript_path = workdir / "TRANSCRIPT.md"
    scripts_dir = workdir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    # transcript logger: append key bash commands + results (persists across
    # sessions). Skip binary/non-UTF8 content that pollutes the file.
    def log_transcript(entry):
        entry = str(entry)
        try:
            entry.encode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return  # skip binary output
        if len(entry) > 500:
            entry = entry[:500] + "..."
        if sum(1 for c in entry if ord(c) > 127) > len(entry) * 0.3:
            return  # >30% non-ASCII = likely binary garbage
        try:
            with open(transcript_path, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except OSError:
            pass

    # boot grace (don't attack a booting service)
    _wait_targets_ready(addrs, events)
    tctx.start_ts = time.time()

    # build target message with prior-work detection
    challenge_msg = (
        f"Target: {code}\n"
        f"target addresses: {addrs}\n"
        f"description:\n{ch.get('description')}\n\n"
        f"⚠ TARGET LOCK: Use ONLY {addrs[0] if addrs else 'N/A'} — "
        f"do NOT probe or attack neighbor IPs (scope discipline). If "
        f"unreachable, wait 60s and retry (services boot in 30-90s).\n"
        f"\nTime budget: ~{budget_min:.0f} minutes. "
        f"Model: {model_name}.\n")

    # strategy reset on re-runs (agents re-read the same notes and repeat
    # the same dead-end approaches)
    if attempt >= 2:
        focus = _ATTEMPT_FOCUS[(attempt - 2) % len(_ATTEMPT_FOCUS)]
        challenge_msg += (
            f"\n🔄 STRATEGY RESET (re-run {attempt}): every prior approach on "
            f"this target failed to exhaust it — do NOT repeat them. Read the "
            f"notes only to know what is already ruled out. "
            f"Suggested focus for variety (override ONLY with clear notes "
            f"evidence another angle is better): {focus}\n")

    # parallel lens: each model gets a different attack-class focus so the
    # lineup spreads instead of duplicating the same recon
    if lens:
        challenge_msg += (
            f"\n🎯 YOUR ASSIGNED LENS: {lens}\n"
            "Parallel models took OTHER lenses — don't duplicate their recon; "
            "diverge from them and go deep on yours. (Suggested only: hard "
            "evidence always overrides.)\n")

    # payload anti-repetition ledger: mechanically extract ALREADY-TRIED
    # commands from TRANSCRIPT (re-runs and long sessions otherwise re-fire
    # the same payloads because nobody remembered what was already sent).
    # Inject the most-repeated ones as a do-not-rerun list.
    try:
        import collections as _coll
        tried = _coll.Counter()
        for ln in transcript_path.read_text(
                encoding="utf-8", errors="replace").splitlines():
            if ln.startswith("$ [") and "] " in ln:
                cmd = ln.split("] ", 1)[1].strip()[:160]
                if len(cmd) > 12:
                    tried[cmd] += 1
        hot = [(c, n) for c, n in tried.most_common(15) if n >= 3]
        if hot:
            challenge_msg += (
                "\n⛔ ALREADY TRIED (mechanically extracted, each run "
                "multiple times WITHOUT yielding a finding — do NOT re-run "
                "verbatim; only meaningfully TRANSFORMED variants):\n")
            for c, n in hot:
                challenge_msg += f"  ({n}x) {c}\n"
    except OSError:
        pass

    # detect prior work files
    prior_items = []
    # per-model thinking files (current architecture) + legacy shared board
    for nf in sorted(workdir.glob("NOTES_*.md")):
        prior_items.append(f"{nf.name} (findings from "
                           f"{nf.stem.replace('NOTES_', '')})")
    if notes_path.exists():
        prior_items.append("NOTES.md (legacy shared findings)")
    if state_path.exists():
        prior_items.append("STATE.md (legacy hand-off)")
    for sf in sorted(workdir.glob("HANDOFF_*.md")):
        prior_items.append(f"{sf.name} (hand-off from "
                           f"{sf.stem.replace('HANDOFF_', '')} — READ FIRST)")
    for sf in sorted(workdir.glob("SUMMARY_*.md")):
        prior_items.append(f"{sf.name} (auto digest from "
                           f"{sf.stem.replace('SUMMARY_', '')})")
    try:
        sfiles = list(scripts_dir.glob("*"))
        if sfiles:
            prior_items.append(f"scripts/ ({len(sfiles)} reusable script(s))")
    except OSError:
        pass
    if transcript_path.exists():
        prior_items.append("TRANSCRIPT.md (command log from prior sessions)")
    if (workdir / "RECON.md").exists():
        prior_items.append("RECON.md (shared recon inventory: fingerprint/"
                           "ports/endpoints/JS routes — DO NOT re-scan what it "
                           "already lists; extend it with new findings only)")
    if (workdir / "INFRA.md").exists():
        prior_items.append("INFRA.md (bg tasks from prior/parallel models: "
                           "proxies, tunnels, scans — logs & ports; note the "
                           "runner reaps processes at run end, logs persist)")

    if prior_items:
        challenge_msg += (
            f"\n⚠ PRIOR WORK DETECTED — this target was tested before.\n"
            f"Before doing anything else, read these files to inherit prior work:\n")
        for item in prior_items:
            challenge_msg += f"  - read_file('{item.split(' ')[0]}')\n"
        challenge_msg += (
            f"\nDo NOT redo work that prior sessions already completed. "
            f"Continue from where they stopped.\n")
    else:
        challenge_msg += (
            f"\nNo prior work found — this is the first session. "
            f"Start with reconnaissance.\n")

    # STEP 0 two-phase: first session = fresh full analysis; re-runs =
    # replan on top of accumulated evidence (fresh re-analysis every round
    # would just re-derive the same dead ends)
    if attempt == 1:
        challenge_msg += (
            f"\n📋 STEP 0 — MANDATORY ANALYSIS (before any other tool "
            f"call): notes(kind='idea') your written analysis: (1) 判断——目标"
            f"描述/指令里哪些指纹词指向什么漏洞类（对照 system prompt 的指纹"
            f"表）；(2) 预计攻击路径——按步骤列出 1-2-3；(3) 最便宜的验证实验——"
            f"第一个该打的探针。THEN execute the plan, starting with the "
            f"cheapest verification.\n")
        challenge_msg += (
            f"\n🔍 STEP 1 — MANDATORY RECON (~3 min, BEFORE exploitation; write "
            f"results to shared RECON.md via write_file — siblings read it "
            f"instead of re-scanning):\n"
            f"1. 指纹全谱: `curl -sI 目标` → Server/X-Powered-By/框架头；"
            f"Cookie 名（JSESSIONID=Java、PHPSESSID=PHP、ASP.NET_SessionId、"
            f"laravel/cloudflare/session=各框架）；whatweb 目标；404 页形状+"
            f"favicon；`curl -s -X OPTIONS -i 目标`（Allow 方法）\n"
            f"2. 组件探测路径（一条 for 循环全打）: /actuator /env /druid "
            f"/swagger-ui.html /v2/api-docs /graphql /_layouts/15/ /wp-admin "
            f"/admin /api /debug /.env /console\n"
            f"3. 端口与服务版本: port_scan(host, 'top100')；可疑口再 "
            f"`nmap -sV -p 端口`\n"
            f"4. robots.txt + sitemap.xml\n"
            f"5. JS 面: 首页所有 <script src> 下载到 js/ 目录 → "
            f"`grep -roE \"(/[a-z0-9_\\-./]+)\" js/ | sort -u` 提取全部路由 → "
            f"grep api/key/token/secret\n"
            f"RECON.md 格式: ## 指纹 ## 端口/服务 ## 发现的端点 ## JS 提取的"
            f"路由与密钥线索。若 RECON.md 已存在（兄弟模型写过）：先读，只允许"
            f"用 bash `cat >> RECON.md` 追加新发现——严禁 write_file 覆盖。"
            f"写完再开始按 STEP 0 计划攻击。\n")
    else:
        challenge_msg += (
            f"\n📋 STEP 0 — REPLAN (before any other tool call): 结合 NOTES 里"
            f"各模型的结论与上面的⛔已试清单，notes(kind='idea') 写出本轮重"
            f"规划：(1) 之前各轮分别试了什么、死在哪；(2) 本轮打法与之前**不同"
            f"在哪**（换引擎/换层/换参数族/换协议）；(3) 为什么预期这次能推进。"
            f"写不出实质差异就先攻击其他漏洞类。\n")
    challenge_msg += (
        f"\n🗂️ FILE MAP（谁写谁读，别混）:\n"
        f"- NOTES_{model_name}.md —— 你私有的思考（追加；兄弟 2min 同步时读）\n"
        f"- RECON.md —— 共享侦察清单（**只准 cat >> 追加**，首写者建）\n"
        f"- TRANSCRIPT.md —— 共享命令日志（自动记，查'谁在何时跑了什么'）\n"
        f"- INFRA.md —— 共享后台任务台账（自动记）\n"
        f"- HANDOFF_{model_name}.md —— 你轮末手写交接（write_file，独占命名）\n"
        f"- SUMMARY_*.md —— 轮末自动摘要（机器生成，别手改）\n"
        f"- scripts/、out/*.log —— 可复用脚本、命令全量日志\n"
        f"\n🧠 INDEPENDENT-THEN-SYNC (parallel models work this target):\n"
        f"- Your PRIVATE notes file is NOTES_{model_name}.md (every notes() "
        f"call writes there, tagged [kind|time]). Think for yourself first — "
        f"do NOT anchor on siblings' conclusions before forming your own.\n"
        f"- The RAW layer is SHARED: TRANSCRIPT.md (all commands+outputs), "
        f"scripts/, INFRA.md, RECON.md. Check TRANSCRIPT before re-running "
        f"anything.\n"
        f"- Every ~2 minutes you'll get a [sync] nudge: then read your "
        f"siblings' NOTES_*.md. Adopt what helps; when a sibling's result "
        f"DIFFERS from yours that is a NEW LEAD, not an error — add the "
        f"difference to your ideas and keep attacking (replay your command "
        f"to check reproducibility; a target state that changed mid-run "
        f"means an action caused it — that action is often the vuln).\n"
        f"- Write RAW observations + your reading ('GET /admin -> 403, "
        f"role=guest: auth required'), not bare conclusions.\n"
        f"Save reusable scripts to scripts/ directory. "
        f"Check cloud metadata where relevant: "
        f"http://169.254.169.254/latest/meta-data/. "
        f"Prove and REPORT every vulnerability you find via submit_flag.\n"
        f"Before calling finish(), write HANDOFF_{model_name}.md via "
        f"write_file —— 你的交接：关键结论、未走完的攻击线、给下一位的"
        f"建议步骤（自动摘要不会替代它）。")
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": challenge_msg}]

    start = time.time()
    deadline = start + budget_min * 60
    steps = 0
    hard = (ch.get("difficulty") or "").lower() == "hard"
    warned_flush = False
    last_sync = time.time()

    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            break
        # context compaction (reuse fact-aware compact)
        if ctxmod.estimate_tokens(messages) > cfg.ctx_compact_ratio * cfg.ctx_limit:
            messages = ctxmod.compact(
                messages, llm,
                (PROMPTS_DIR / "compact.md").read_text(encoding="utf-8"))
            messages.append({"role": "user",
                             "content": "[context compacted] Read the "
                                        "NOTES_*.md / RECON.md / HANDOFF_*.md "
                                        "files (read_file) for accumulated "
                                        "findings. Check scripts/ for reusable "
                                        "code before continuing."})
        # thinking mode
        if not send_thinking:
            thinking = None
        elif cfg.thinking == "auto":
            thinking = "on" if hard else "off"
        else:
            thinking = cfg.thinking
        # LLM call
        try:
            res = llm.chat(messages, tools=schemas, thinking=thinking)
        except QuotaExhausted:
            raise
        except Exception as e:  # noqa: BLE001
            events.log("coding_llm_error", code=code, model=model_name,
                       error=str(e)[:200])
            break
        messages.append(_assistant_msg(res))
        events.log("llm_call", model=res.model, usage=res.usage,
                   tool_calls=[c.name for c in res.tool_calls],
                   coding=model_name, code=code)
        if not res.tool_calls:
            messages.append({"role": "user", "content":
                             "Respond with tool calls only (or finish)."})
            steps += 1
            continue

        # tool dispatch (contiguous per OpenAI contract)
        tool_msgs = []
        for call in res.tool_calls:
            fn = tools.get(call.name)
            if fn is None:
                result = f"[unknown tool: {call.name}]"
            else:
                try:
                    result = fn(**call.arguments)
                except Exception as e:  # noqa: BLE001
                    result = f"[tool error] {type(e).__name__}: {e}"
            events.log("tool_call", tool=call.name,
                       args=json.dumps(call.arguments, ensure_ascii=False)[:200],
                       coding=model_name, code=code)
            # transcript: log bash commands + key results for later sessions
            if call.name == "bash":
                cmd = str(call.arguments.get("command", ""))[:200]
                log_transcript(f"$ [{model_name}] {cmd}")
                log_transcript(f"> {result[:300]}")
            tool_msgs.append({"role": "tool", "tool_call_id": call.id,
                              "content": result})
        messages.extend(tool_msgs)
        steps += 1

        # finish() is honored immediately — the tool's contract says it ends
        # the session; without this check a finishing model spins until the
        # budget expires
        if getattr(tctx, "finished", False):
            break

        # time-based sibling sync (every ~2min): cross-read siblings' PRIVATE
        # notes — adopt useful findings; DIVERGENT results are new leads to
        # add to your own ideas, never grounds to abandon your line
        if time.time() - last_sync > 120:
            sibs = [p.name for p in workdir.glob("NOTES_*.md")
                    if p.name != my_notes.name]
            if sibs:
                messages.append({"role": "user",
                                 "content": "[sync] 2 minutes elapsed — cross-read "
                                            "siblings' notes now: read_file("
                                            + ", ".join(f"'{n}'" for n in sibs)
                                            + "). Adopt what helps; where a "
                                              "sibling's result DIFFERS from "
                                              "yours, treat it as a new lead "
                                              "and expand your attack. Then "
                                              "continue your own line."})
            last_sync = time.time()

        # near-deadline flush: the budget cut is hard, so warn once ~3 min out
        # and have the agent persist its in-flight attack line — an abrupt cut
        # mid-brute-force/mid-exploit-chain otherwise loses the context
        if not warned_flush and time.time() > deadline - 180:
            warned_flush = True
            messages.append({"role": "user",
                             "content": "[TIME] Under 3 minutes left in this session. "
                                        "NOW: stop starting anything new; notes(kind="
                                        "'fact') everything about your CURRENT attack "
                                        "line (exact commands, progress, where it "
                                        "stops); save working scripts to scripts/; "
                                        "write HANDOFF_" + model_name + ".md with "
                                        "precise next steps. Whoever comes next "
                                        "inherits exactly what you save."})

    elapsed = round(time.time() - start, 1)
    stopped = stop_event is not None and stop_event.is_set()

    # NOTE: process cleanup (bg tasks, `cmd &` stragglers, proxies/tunnels)
    # is the RUNNER's job at run end (after all parallel models joined)
    # — a per-model kill here could yank a proxy a sibling model is still
    # actively using via the shared INFRA coordination.

    # ---- budget drain turn ----
    # The budget cut is hard, but the model never got to digest its LAST tool
    # results (they landed in `messages` after the final LLM call). Give it
    # one bounded wrap-up turn: persist-only (notes/write_file/finish) — no
    # new attacks. Skipped when a sibling stopped the run (stop_event).
    if time.time() >= deadline and not stopped:
        try:
            messages.append({"role": "user",
                             "content": "[DEADLINE] Budget exhausted — this is your "
                                        "FINAL turn. Digest your last tool results "
                                        "now: notes(kind='fact'/'failure', ...) the "
                                        "outcome, write_file HANDOFF_" + model_name +
                                        ".md with exact next steps for whoever "
                                        "continues, save any working scripts. "
                                        "Attack tool calls will be "
                                        "rejected — finish() when done."})
            res = llm.chat(messages, tools=schemas, thinking=None)
            messages.append(_assistant_msg(res))
            for call in (res.tool_calls or []):
                if call.name not in ("notes", "write_file", "finish",
                                     "read_file", "bash_status"):
                    result = ("[DEADLINE] rejected — persist-only turn "
                              "(notes/write_file/finish).")
                else:
                    try:
                        result = tools[call.name](**call.arguments)
                    except Exception as e:  # noqa: BLE001
                        result = f"[tool error] {type(e).__name__}: {e}"
                events.log("drain_tool", tool=call.name, coding=model_name,
                           code=code)
                messages.append({"role": "tool", "tool_call_id": call.id,
                                 "content": result})
            events.log("drain_done", code=code, model=model_name,
                       calls=len(res.tool_calls or []))
        except Exception as e:  # noqa: BLE001 — drain must never crash the session
            events.log("drain_error", code=code, model=model_name,
                       error=str(e)[:150])

    elapsed = round(time.time() - start, 1)
    gave_up = time.time() >= deadline
    stopped = stop_event is not None and stop_event.is_set()

    # write an auto digest for the next session / parallel agent
    state_lines = [
        f"# Target {code} — {model_name} session",
        f"## Outcome: {'STOPPED (run ended)' if stopped else 'BUDGET EXHAUSTED' if gave_up else 'FINISHED'}",
        f"## Steps: {steps}, Elapsed: {elapsed}s, Time: {time.strftime('%H:%M:%S')}",
        f"## Key findings (from NOTES_{model_name}.md):",
    ]
    try:
        notes_content = my_notes.read_text(encoding="utf-8")[:2000]
        state_lines.append(notes_content if notes_content.strip() else "(none)")
    except OSError:
        state_lines.append("(none)")
    scripts_list = list(scripts_dir.glob("*")) if scripts_dir.exists() else []
    state_lines.append(f"\n## Reusable scripts in scripts/: {len(scripts_list)}")
    for s in scripts_list[:10]:
        state_lines.append(f"  - {s.name}")
    state_lines.append(
        "\n## Next steps for the next agent:\n"
        "Read NOTES_*.md for full findings. Read TRANSCRIPT.md for command log. "
        "Check scripts/ for reusable code. Continue from where this session stopped.")
    try:
        (workdir / f"SUMMARY_{model_name}.md").write_text("\n".join(state_lines), encoding="utf-8")
    except OSError:
        pass

    events.log("coding_end", code=code, model=model_name, steps=steps,
               elapsed=elapsed, gave_up=gave_up, stopped=stopped)
    return CodingOutcome(finished=True, gave_up=gave_up, steps=steps,
                         elapsed=elapsed, model=model_name,
                         pgids=list(tctx.pgids))

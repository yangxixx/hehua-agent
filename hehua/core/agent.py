"""Solving agent: LLM tool-use loop + rule-based watchdog (no self-reported exit)."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import Config
from ..llm.client import LLMClient
from . import context as ctxmod
from .knowledge import Knowledge, family_of
from .memory import Notes
from .tools import ToolContext, build_schemas, build_tools

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


def pick_playbook(description: str, code: str = "") -> str:
    """Choose the playbook for a challenge.

    the platform taxonomy is encoded in the challenge-code prefix — it is
    AUTHORITATIVE (prior-run audit: keyword matching gave ALL 9 c- challenges
    the web playbook, so the product-recipe table never reached them; b-01/
    b-02 and most f1/e-series were misrouted too). Keywords remain only as
    a fallback for non-platform challenge sets (XBOW local practice)."""
    pre = (code or "").lower()
    if pre.startswith(("b-", "b0")):
        return "playbook_killchain.md"
    if pre.startswith(("c-", "c0")):
        return "playbook_exploit.md"
    if pre.startswith(("d-", "d0")):
        return "playbook_cloud.md"
    if pre.startswith(("e1", "e2", "e3")):
        return "playbook_evasion.md"
    if pre.startswith(("f1", "f2")):
        return "playbook_binary.md"
    if pre.startswith(("a-", "a0")):
        return "playbook_web.md"
    # 8/16 new dimensions (prefix scheme unknown pre-competition) — best-effort
    # prefix guesses, then keyword fallback. Distinctive terms, checked first.
    if pre.startswith(("ai-", "llm-", "gpt-", "bot-")):
        return "playbook_ai.md"
    if pre.startswith(("bc-", "chain-", "eth-", "sol-", "block-")):
        return "playbook_blockchain.md"
    d = (description or "").lower()
    if any(k in d for k in ("区块链", "智能合约", "合约", "solidity", "以太坊",
                             "ethereum", "web3", "链上", "代币", "dao", "reentrancy",
                             "blockchain", "erc20", "erc-20")):
        return "playbook_blockchain.md"
    if any(k in d for k in ("大模型", "llm", "提示注入", "prompt injection", "ai agent",
                             "智能体", "chatbot", "聊天机器人", "rag", "langchain",
                             "function calling", "mcp", "jailbreak", "越狱")):
        return "playbook_ai.md"
    if any(k in d for k in ("内网", "横向", "域", "killchain", "多阶段", "pivot")):
        return "playbook_killchain.md"
    if any(k in d for k in ("二进制", "pwn", "逆向", "reverse", "rop", "binary")):
        return "playbook_binary.md"
    if any(k in d for k in ("云", "cloud", "k8s", "kubernetes", "iam", "docker", "容器逃逸")):
        return "playbook_cloud.md"
    if any(k in d for k in ("waf", "规避", "免杀", "edr", "evasion", "绕过检测")):
        return "playbook_evasion.md"
    if any(k in d for k in ("exploit", "利用", "poc", "cve-", "提权")):
        return "playbook_exploit.md"
    return "playbook_web.md"


class Watchdog:
    """Rule-based Observer: repetition + no-progress detection."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._last_hashes: list[str] = []
        self._steps_since_progress = 0

    def observe(self, tool_name: str, args: dict, progress: bool) -> list[str]:
        injections = []
        if tool_name == "bash":
            h = hashlib.md5(str(args.get("command", "")).encode()).hexdigest()
            self._last_hashes.append(h)
            self._last_hashes = self._last_hashes[-3:]
            if len(self._last_hashes) == 3 and len(set(self._last_hashes)) == 1:
                injections.append(
                    "[watchdog] You have run the SAME command 3 times in a row. "
                    "Change approach: different payload/endpoint/tool, or finish.")
                self._last_hashes.clear()
        if progress:
            self._steps_since_progress = 0
        else:
            self._steps_since_progress += 1
            if self._steps_since_progress >= self.cfg.no_progress_steps:
                injections.append(
                    "[watchdog] No progress for 8 steps. Consult your playbook's "
                    "checklist and switch direction; record failed ideas as "
                    "notes(failure) and try an untested class of vulnerability.")
                self._steps_since_progress = 0
        return injections


@dataclass
class Outcome:
    finished: bool
    gave_up: bool
    steps: int
    elapsed: float
    summary: str


_PRODUCT_HINTS = ("1panel", "泛微", "weaver", "seeyon", "用友", "yonyou", "通达",
                  "tongda", "shiro", "spring", "thinkphp", "weblogic", "tomcat",
                  "jenkins", "confluence", "gitlab", "wordpress", "drupal",
                  "phpmyadmin", "redis", "fastjson", "log4j", "oa")


def _wait_targets_ready(addrs: list, events, grace_sec: float = 90.0) -> None:
    """TCP-probe target ports until one answers or the grace window expires.

    prior-run c-04 regression: Java-based containers (GeoServer/Langflow...)
    take 30-90s to boot; the agent saw connection-refused and gave up inside
    6 minutes with zero facts — which also locked the retry gate. Waiting
    here costs nothing (it happens before the per-challenge clock starts)."""
    import socket
    targets = []
    for a in addrs or []:
        host, _, port = str(a).rpartition(":")
        if host and port.isdigit():
            targets.append((host, int(port)))
    if not targets:
        return
    deadline = time.time() + grace_sec
    waited = 0.0
    while True:
        for host, port in targets:
            s = socket.socket()
            s.settimeout(3)
            try:
                s.connect((host, port))
                if waited:
                    events.log("target_ready_after_wait",
                               addr=f"{host}:{port}", waited=round(waited))
                return
            except OSError:
                pass
            finally:
                s.close()
        if time.time() >= deadline:
            events.log("target_unreachable_grace",
                       addrs=[str(a) for a in addrs][:3], waited=round(waited))
            return
        time.sleep(5)
        waited += 5


def _nuclei_prescan(ch: dict, addrs: list, events) -> str | None:
    """Code-level hard injection: known-product/CVE classes get a nuclei
    pre-scan whose hits are force-fed into the context (round-2 lesson:
    the model ignores playbook advice to run nuclei — 1 call in 6h)."""
    code = ch.get("unique_code", "")
    desc = (ch.get("description") or "").lower()
    is_cve_class = code.startswith("c-") or any(h in desc for h in _PRODUCT_HINTS)
    if not is_cve_class or not addrs:
        return None
    import shutil as _sh
    import subprocess
    proj = Path(__file__).resolve().parents[2]
    # local Windows dev: tools/nuclei.exe; hosted linux image: PATH + /opt
    nuc = None
    for cand in (proj / "tools" / "nuclei.exe", Path("/usr/local/bin/nuclei")):
        if cand.exists():
            nuc = cand
            break
    if nuc is None:
        w = _sh.which("nuclei")
        if w:
            nuc = Path(w)
    tpls = proj / "tools" / "nuclei-templates"
    if not tpls.exists():
        tpls = Path("/opt/nuclei-templates")
    if nuc is None or not tpls.exists():
        return None
    target = addrs[0]
    if not target.startswith("http"):
        target = f"http://{target}"
    try:
        p = subprocess.run(
            [str(nuc), "-u", target,
             "-t", str(tpls / "http"),  # cves+vulnerabilities live under http/
             "-severity", "critical,high", "-c", "4", "-timeout", "10",
             "-duc", "-silent"],
            capture_output=True, text=True, timeout=150, errors="replace")
        out = (p.stdout or "").strip()
    except Exception as e:  # noqa: BLE001 — prescan is best-effort
        events.log("prescan_error", error=str(e)[:150])
        return None
    if out:
        events.log("prescan", code=code, hits=out.count("\n") + 1)
        return out[:3000]
    events.log("prescan_empty", code=code, rc=getattr(p, "returncode", -1),
               err=(p.stderr or "")[:120])
    return None


def solve_challenge(ch: dict, addrs: list, cfg: Config, llm: LLMClient,
                    notes: Notes, submit_fn, events, workdir: Path,
                    budget_min: float = 8.0, hint: str | None = None,
                    intel: str | None = None,
                    send_thinking: bool = True,
                    self_assess: bool = False,
                    stop_event=None,
                    direction: str | None = None,
                    dead_ends: list | None = None) -> Outcome:
    system = (PROMPTS_DIR / "system.md").read_text(encoding="utf-8")
    pb = pick_playbook(ch.get("description", ""), ch.get("unique_code", ""))
    system += "\n\n---\n" + (PROMPTS_DIR / pb).read_text(encoding="utf-8")

    tctx = ToolContext(workdir=workdir, notes=notes, submit_fn=submit_fn, addrs=addrs)
    tools = build_tools(tctx, cfg)
    schemas = build_schemas()
    watchdog = Watchdog(cfg)

    challenge_msg = (
        f"Challenge: {ch.get('unique_code')}\n"
        f"difficulty: {ch.get('difficulty')} | flags total: {ch.get('flag_count')}\n"
        f"target addresses (VPN-reachable): {addrs}\n"
        f"description:\n{ch.get('description')}\n\n"
        f"Time budget for this challenge: ~{budget_min:.0f} minutes. "
        "Start with reconnaissance (crawl + dir scan) before attacking.")
    if hint:
        challenge_msg += (f"\n\nOFFICIAL HINT (score for this challenge is "
                          f"discounted):\n{hint}")
    # boot grace BEFORE prescan + clock: scanning a still-booting container
    # wastes the prescan window and misses every hit (prior-run c-series)
    _wait_targets_ready(addrs, events)
    tctx.start_ts = time.time()  # finish-guard clock = actual work clock
    prescan = _nuclei_prescan(ch, addrs, events)
    if prescan:
        challenge_msg += ("\n\nNUCLEI PRE-SCAN HITS (authoritative leads — "
                          "verify each hit by hand, read the matched template "
                          "YAML, then exploit):\n" + prescan)
    if intel:
        challenge_msg += ("\n\nPREVIOUS ATTEMPT INTELLIGENCE (your prior self "
                          "died one step short — start FROM these leads, do "
                          "not re-derive):\n" + intel)
    # Cross-challenge knowledge (cross-challenge reuse pattern): seed with PROVEN recipes
    # from already-solved sibling challenges in the same family — a working PoC
    # for c-02 is a head-start for c-03. Best-effort; never block a solve on it.
    try:
        kint = Knowledge(workdir.parent / "knowledge.jsonl").intel_block(
            family_of(ch.get("unique_code", "")))
        if kint:
            challenge_msg += ("\n\nPRIOR SOLVES in this challenge family — these "
                              "approaches ALREADY WORKED on siblings; if the same "
                              "product/pattern appears, reuse the exact payload "
                              "instead of re-deriving:\n" + kint)
    except Exception:  # noqa: BLE001
        pass
    if direction:
        challenge_msg += (f"\n\nDEEP-MODE PEER ASSIGNMENT: you are one of several agents "
                          f"attacking this SAME target in PARALLEL. Your assigned focus: "
                          f"**{direction}**. Another peer covers a different angle — do NOT "
                          f"duplicate; share every finding immediately via notes(kind=fact), "
                          f"and if you reach the flag submit_flag at once.")
    if dead_ends:
        challenge_msg += ("\n\nDEAD ENDS — these EXACT approaches were already tried "
                          "and FAILED (by a prior attempt or a sibling peer). Do NOT "
                          "repeat them; pick a different angle:\n- "
                          + "\n- ".join(str(d)[:160] for d in dead_ends[:8]))
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": challenge_msg}]

    start = time.time()
    hard_sec = budget_min * 60
    soft_sec = hard_sec * 0.8
    soft_warned = False
    steps = 0
    no_tool_streak = 0

    hard_q = (ch.get("difficulty") or "").lower() == "hard"
    think_mode = cfg.thinking
    extended = False
    assessed = False  # one-shot self-assessment extension (GLM escalation)

    while not tctx.finished and steps < cfg.max_steps:
        # deep-mode peers bail the moment a sibling peer submits the flag
        if stop_event is not None and stop_event.is_set():
            break
        elapsed = time.time() - start
        if elapsed >= hard_sec:
            if self_assess and not assessed:
                # At the limit, let the (strong) model judge for itself: is a
                # concrete path to the flag in reach? Grant ONE extension and
                # leave the continue-vs-finish call to it (prior-run directive).
                assessed = True
                grant = min(600.0, hard_sec * 0.5)
                hard_sec += grant
                events.log("self_assess_grant", code=ch.get("unique_code"),
                           extra_min=round(grant / 60, 1))
                messages.append({"role": "user", "content":
                    "[budget] You have hit this challenge's time limit. Before "
                    "we cut you off, self-assess HONESTLY: do you have a "
                    "CONCRETE, executable path to the flag (not a hunch)? If "
                    "YES, keep working — you are granted a short final "
                    "extension — and execute that path NOW. If you have no real "
                    "path, call finish(give_up) immediately and record what you "
                    "learned as notes(failure) for future attempts."})
            else:
                break
        if not soft_warned and elapsed >= soft_sec:
            soft_warned = True
            # kill-chain-detected extension: if leads are hot, buy +25% time
            # instead of dying one step short (a-18/d-04/c-03 lesson)
            hot = any(k in notes.snapshot(8).lower() for k in
                      ("key", "cve", "alias", "token", "credential", "secret",
                       "default", "proxy", "rce", "bypass worked", "exec"))
            if hot and not extended:
                extended = True
                hard_sec *= 1.25
                events.log("budget_extend", code=ch.get("unique_code"),
                           new_hard_min=round(hard_sec / 60, 1))
                messages.append({"role": "user", "content":
                                 "[watchdog] Kill chain looks HOT — budget "
                                 "extended 25%. EXECUTE the direct chain NOW."})
            else:
                messages.append({"role": "user", "content":
                                 "[watchdog] 80% of this challenge's time budget used. "
                                 "Submit everything you have, then finish soon; record "
                                 "untested directions as notes(idea) for the second pass."})
        if ctxmod.estimate_tokens(messages) > cfg.ctx_compact_ratio * cfg.ctx_limit:
            messages = ctxmod.compact(
                messages, llm,
                (PROMPTS_DIR / "compact.md").read_text(encoding="utf-8"),
                notes=notes)
            # memory anchor: the summary is lossy; notes.jsonl is not.
            # Re-inject it so continuations never re-try recorded dead ends.
            snap = notes.snapshot(20)
            if snap and snap != "(no notes yet)":
                messages.append({"role": "user", "content":
                                 "[memory anchor] durable notes (survived "
                                 "compaction) — cross-check BEFORE acting; "
                                 "never repeat a recorded failure:\n" + snap})
        # auto: think on hard challenges & retries-with-hint; off on quick
        # classes to save latency/tokens (verified: disable param supported).
        # send_thinking=False (GLM escalation) omits the deepseek-only param —
        # GLM-5.2 reasons by default and rejects the foreign `thinking` field.
        if not send_thinking:
            thinking = None
        elif think_mode == "auto":
            thinking = "on" if (hard_q or hint) else "off"
        else:
            thinking = think_mode
        res = llm.chat(messages, tools=schemas, thinking=thinking)
        messages.append(_assistant_msg(res))
        events.log("llm_call", model=res.model, usage=res.usage,
                   tool_calls=[c.name for c in res.tool_calls])
        if not res.tool_calls:
            # prior-run: 149 "tool calls only" injections — agents that keep
            # narrating instead of acting burn full-context LLM calls until
            # the budget bleeds out. Three refusals in a row = forced stop
            # (notes survive for the retry pass).
            no_tool_streak += 1
            if no_tool_streak >= 3:
                events.log("forced_stop_no_tools", code=ch.get("unique_code"),
                           streak=no_tool_streak)
                break
            messages.append({"role": "user", "content":
                             "Respond with tool calls only (or finish)."})
            steps += 1
            continue
        no_tool_streak = 0
        # tool results must be appended contiguously right after the
        # assistant tool_calls message (OpenAI contract); watchdog injections
        # go in only after the whole tool block.
        tool_msgs, injections = [], []
        for call in res.tool_calls:
            fn = tools.get(call.name)
            if fn is None:
                result = f"[unknown tool: {call.name}]"
            else:
                try:
                    result = fn(**call.arguments)
                except Exception as e:  # noqa: BLE001 — tool errors are feedback
                    result = f"[tool error] {type(e).__name__}: {e}"
            events.log("tool_call", tool=call.name, args=_short(call.arguments))
            progress = _is_progress(call.name, call.arguments, tctx)
            for inj in watchdog.observe(call.name, call.arguments, progress):
                events.log("watchdog", injection=inj)
                injections.append(inj)
            tool_msgs.append({"role": "tool", "tool_call_id": call.id,
                              "content": result})
        messages.extend(tool_msgs)
        for inj in injections:
            messages.append({"role": "user", "content": inj})
        steps += 1

    if not tctx.finished:  # budget/steps exhausted: external hard stop
        tctx.finished = True
        tctx.gave_up = True
        tctx.finish_summary = "forced stop (budget/steps)"
    return Outcome(finished=True, gave_up=tctx.gave_up, steps=steps,
                   elapsed=round(time.time() - start, 1),
                   summary=tctx.finish_summary)


def _assistant_msg(res) -> dict:
    m: dict = {"role": "assistant", "content": res.content}
    if res.tool_calls:
        m["tool_calls"] = [{"id": c.id, "type": "function",
                            "function": {"name": c.name,
                                         "arguments": json.dumps(
                                             c.arguments, ensure_ascii=False)}}
                           for c in res.tool_calls]
    return m


def _is_progress(tool_name: str, args: dict, tctx: ToolContext) -> bool:
    if tool_name == "notes" and args.get("kind") == "fact":
        return True
    if tool_name == "submit_flag" and tctx.last_submit \
            and tctx.last_submit.get("correct"):
        return True
    return False


def _short(d: dict, n: int = 200) -> str:
    return json.dumps(d, ensure_ascii=False)[:n]

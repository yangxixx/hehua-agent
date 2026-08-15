"""Coding-agent solve loop: continuous tool-use, NOTES.md memory, no blackboard.

This is the bsrc-agent pattern (proven at 95.66): one unbroken chain-of-thought
per challenge per model — LLM thinks → bash/http/exploit → observe → repeat →
submit. Memory = NOTES.md (a file agents read/write). Zero orchestration overhead
(no Reason/Intent/blackboard).

Supports parallel multi-model: multiple coding agents work the same challenge,
sharing NOTES.md (stigmergy) + stop_event (first flag wins).
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
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
                 system_name: str = "system_coding.md") -> CodingOutcome:
    """One continuous coding-agent session for one challenge with one model.

    No Reason/Intent/blackboard — just think→tool→observe→repeat.
    Writes findings to NOTES.md (shared with parallel agents via notes_lock).
    Ends on finish, stop_event (sibling solved), or budget.
    """
    code = ch.get("unique_code", "")
    system = (PROMPTS_DIR / system_name).read_text(encoding="utf-8")
    pb = pick_playbook(ch.get("description", ""), code)
    system += "\n\n---\n" + (PROMPTS_DIR / pb).read_text(encoding="utf-8")
    if pb in ("playbook_killchain.md", "playbook_exploit.md"):
        try:
            system += "\n\n---\n" + (PROMPTS_DIR / "poc_inventory.md").read_text(
                encoding="utf-8")
        except OSError:
            pass

    # notes tool → append to NOTES.md (shared memory, thread-safe)
    notes_path = workdir / "NOTES.md"

    def notes_sink(kind, content):
        line = f"[{kind}] {content}"
        try:
            if notes_lock:
                with notes_lock:
                    with open(notes_path, "a", encoding="utf-8") as f:
                        f.write(line + "\n")
            else:
                with open(notes_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except OSError:
            pass
        return f"noted [{kind}] {str(content)[:100]}"

    tctx = ToolContext(workdir=workdir, notes=Notes(), submit_fn=submit_fn,
                       addrs=addrs, notes_sink=notes_sink)
    tools = build_tools(tctx, cfg, minimal=True)
    schemas = build_schemas()

    # ---- multi-layer file memory (bsrc-agent pattern) ----
    notes_path = workdir / "NOTES.md"
    state_path = workdir / "STATE.md"
    transcript_path = workdir / "TRANSCRIPT.md"
    scripts_dir = workdir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    # transcript logger: append key bash commands + results (persists across attempts)
    # Skip binary/non-UTF8 content that pollutes the file (f2-05 lesson)
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

    # boot grace (infra — don't attack a booting container)
    _wait_targets_ready(addrs, events)
    tctx.start_ts = time.time()

    # build challenge message with prior-work detection
    challenge_msg = (
        f"Challenge: {code}\n"
        f"difficulty: {ch.get('difficulty')} | flags total: {ch.get('flag_count')}\n"
        f"target addresses: {addrs}\n"
        f"description:\n{ch.get('description')}\n\n"
        f"⚠ TARGET LOCK: Use ONLY {addrs[0] if addrs else 'N/A'} — "
        f"do NOT probe or attack neighbor IPs. If unreachable, wait 60s "
        f"and retry (containers boot in 30-90s). NEVER attack a different IP.\n"
        f"\nTime budget: ~{budget_min:.0f} minutes. "
        f"Model: {model_name}.\n")

    # detect prior work files
    prior_items = []
    if notes_path.exists():
        prior_items.append("NOTES.md (findings from prior attempts)")
    if state_path.exists():
        prior_items.append("STATE.md (where the last attempt stopped)")
    # also check per-model state files (from parallel agents)
    for sf in workdir.glob("STATE_*.md"):
        prior_items.append(f"{sf.name} (state from {sf.stem.replace('STATE_','')})")
    try:
        sfiles = list(scripts_dir.glob("*"))
        if sfiles:
            prior_items.append(f"scripts/ ({len(sfiles)} reusable script(s))")
    except OSError:
        pass
    if transcript_path.exists():
        prior_items.append("TRANSCRIPT.md (command log from prior attempts)")

    if prior_items:
        challenge_msg += (
            f"\n⚠ PRIOR WORK DETECTED — this challenge was attempted before.\n"
            f"Before doing anything else, read these files to inherit prior work:\n")
        for item in prior_items:
            challenge_msg += f"  - read_file('{item.split(' ')[0]}')\n"
        challenge_msg += (
            f"\nDo NOT redo work that prior attempts already completed. "
            f"Continue from where they stopped.\n")
    else:
        challenge_msg += (
            f"\nNo prior work found — this is the first attempt. "
            f"Start with reconnaissance.\n")

    challenge_msg += (
        f"\nWrite ALL key findings to NOTES.md via notes(kind='fact', content='...'). "
        f"Save reusable scripts to scripts/ directory. "
        f"Check cloud metadata: curl -s http://metadata.tencentyun.com/latest/meta-data/ "
        f"and http://169.254.169.254/latest/meta-data/. "
        f"Find and submit all flags.\n"
        f"Before calling finish(), write a STATE.md summarizing what you found "
        f"and what the next agent should try.")
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": challenge_msg}]

    start = time.time()
    deadline = start + budget_min * 60
    steps = 0
    hard = (ch.get("difficulty") or "").lower() == "hard"

    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            break
        # context compaction (reuse fact-aware compact)
        if ctxmod.estimate_tokens(messages) > cfg.ctx_compact_ratio * cfg.ctx_limit:
            messages = ctxmod.compact(
                messages, llm,
                (PROMPTS_DIR / "compact.md").read_text(encoding="utf-8"))
            messages.append({"role": "user",
                             "content": "[context compacted] Read NOTES.md and "
                                        "STATE.md (read_file) for accumulated "
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

        # MULTI-FLAG GATE: if submit said flags remain, block finish and push hunting
        if tctx.last_submit and tctx.last_submit.get("remaining", 0) > 0:
            rem = tctx.last_submit["remaining"]
            if call.name == "finish" or any(
                    c.name == "finish" for c in res.tool_calls):
                tool_msgs.append({"role": "tool", "tool_call_id": call.id,
                                 "content": f"FINISH BLOCKED: {rem} flag(s) still "
                                            f"remain on this challenge. Do NOT stop. "
                                            f"Continue hunting — check other stages, "
                                            f"hosts, roles, params, or files."})
                # Remove finish from tool calls so loop continues
                res.tool_calls = [c for c in res.tool_calls if c.name != "finish"]
                tctx.finished = False
                messages.append(_assistant_msg(res))
                messages.extend(tool_msgs)
                messages.append({"role": "user",
                                 "content": f"[MULTI-FLAG] {rem} flags still remain! "
                                            f"Continue the hunt. Submit immediately "
                                            f"when found."})
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
            # transcript: log bash commands + key results for next attempt
            if call.name == "bash":
                cmd = str(call.arguments.get("command", ""))[:200]
                log_transcript(f"$ [{model_name}] {cmd}")
                log_transcript(f"> {result[:300]}")
            tool_msgs.append({"role": "tool", "tool_call_id": call.id,
                              "content": result})
        messages.extend(tool_msgs)
        steps += 1

        # periodic stigmergy nudge: re-read NOTES.md to pick up parallel agents' findings
        if steps % 10 == 0 and notes_path.exists():
            messages.append({"role": "user",
                             "content": "[parallel-sync] Other agents may have posted "
                                        "new findings. read_file('NOTES.md') to check "
                                        "for updates, then continue."})

    elapsed = round(time.time() - start, 1)
    gave_up = time.time() >= deadline
    stopped = stop_event is not None and stop_event.is_set()

    # write STATE.md for the next attempt / parallel agent
    state_lines = [
        f"# Challenge {code} — {model_name} attempt",
        f"## Outcome: {'STOPPED (sibling solved)' if stopped else 'BUDGET EXHAUSTED' if gave_up else 'FINISHED'}",
        f"## Steps: {steps}, Elapsed: {elapsed}s, Time: {time.strftime('%H:%M:%S')}",
        f"## Key findings (from NOTES.md):",
    ]
    try:
        notes_content = notes_path.read_text(encoding="utf-8")[:2000]
        state_lines.append(notes_content if notes_content.strip() else "(none)")
    except OSError:
        state_lines.append("(none)")
    scripts_list = list(scripts_dir.glob("*")) if scripts_dir.exists() else []
    state_lines.append(f"\n## Reusable scripts in scripts/: {len(scripts_list)}")
    for s in scripts_list[:10]:
        state_lines.append(f"  - {s.name}")
    state_lines.append(
        "\n## Next steps for the next agent:\n"
        "Read NOTES.md for full findings. Read TRANSCRIPT.md for command log. "
        "Check scripts/ for reusable code. Continue from where this attempt stopped.")
    try:
        (workdir / f"STATE_{model_name}.md").write_text("\n".join(state_lines), encoding="utf-8")
    except OSError:
        pass

    events.log("coding_end", code=code, model=model_name, steps=steps,
               elapsed=elapsed, gave_up=gave_up, stopped=stopped)
    return CodingOutcome(finished=True, gave_up=gave_up, steps=steps,
                         elapsed=elapsed, model=model_name)

"""Tool set (9): bash / http_request / file ops / grep / notes / submit_flag / finish."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .memory import Notes
from .sandbox import run_bash

# Flag-format sanity (surgical-submit discipline, à la ATX's 4-failure run).
# submit_flag still accepts anything (wrong submits are free), but a non-match
# warns the agent it likely extracted a truncated/non-flag value.
_UUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")


def _looks_like_flag(s: str) -> bool:
    s = s.strip()
    if not (6 <= len(s) <= 200):
        return False
    if "{" in s and "}" in s:            # flag{...} / ctf{...} / {token}
        return True
    return bool(_UUID.match(s) or _HEX.match(s))


def cap(text: str, max_bytes: int = 8192) -> str:
    if len(text) <= max_bytes:
        return text
    h = max_bytes // 2
    return (text[:h] +
            f"\n... [truncated {len(text)} chars] ...\n" + text[-h:])


@dataclass
class ToolContext:
    workdir: Path
    notes: Notes
    submit_fn: object            # (flag, writeup) -> dict(correct, remaining)
    addrs: list = field(default_factory=list)
    finished: bool = False
    finish_summary: str = ""
    gave_up: bool = False
    last_submit: dict | None = None
    wrong_flags: set = field(default_factory=set)
    start_ts: float = field(default_factory=time.time)
    gate_checked: bool = False     # finish-gate: one forced verify pass
    # swarm: when set, the `notes` tool routes here (Blackboard.add_fact / add_intent)
    # instead of Notes.add — same tool surface feeds the Fact/Intent board.
    notes_sink: object = None


def build_schemas() -> list[dict]:
    def fn(name, desc, props, required):
        return {"type": "function", "function": {
            "name": name, "description": desc,
            "parameters": {"type": "object", "properties": props,
                           "required": required}}}
    return [
        fn("bash", "Run a shell command in the isolated workdir. Long output is "
           "spooled to a log file; you get head+tail and the log path.",
           {"command": {"type": "string"},
            "timeout": {"type": "integer", "description": "seconds, max 300"}},
           ["command"]),
        fn("port_scan", "Bounded TCP port scan via nmap (ALWAYS use this, NEVER a "
           "bash /dev/tcp loop which spawns runaway jobs). host=IP or IP:port; "
           "ports='top100' | '1-1000' | 'full' | '22,80,443'.",
           {"host": {"type": "string"}, "ports": {"type": "string"}},
           ["host"]),
        fn("r2_analyze", "Run radare2 commands on a binary for reverse engineering "
           "(decompile, list functions, find strings, control-flow graph). You "
           "generate r2 commands; the tool executes them and returns structured "
           "output. Examples: 'aaa; afl' (analyze+list funcs), 'pdf @main' "
           "(decompile main), 'iz~flag' (search strings for flag), 'axt @sym' "
           "(cross-references).",
           {"binary": {"type": "string", "description": "path to the binary file"},
            "commands": {"type": "string", "description": "r2 commands separated by ;"}},
           ["binary"]),
        fn("http_request", "Send an HTTP request; returns status, final URL, "
           "headers and (capped) body.",
           {"method": {"type": "string"}, "url": {"type": "string"},
            "headers": {"type": "object"}, "body": {"type": "string"},
            "follow_redirects": {"type": "boolean"}},
           ["url"]),
        fn("read_file", "Read a file (offset/limit in lines).",
           {"path": {"type": "string"}, "offset": {"type": "integer"},
            "limit": {"type": "integer"}}, ["path"]),
        fn("write_file", "Write a file (exploit scripts, payload lists, ...).",
           {"path": {"type": "string"}, "content": {"type": "string"}},
           ["path", "content"]),
        fn("list_dir", "List a directory.", {"path": {"type": "string"}}, ["path"]),
        fn("grep", "Regex-search a file for patterns (returns matching lines).",
           {"pattern": {"type": "string"}, "path": {"type": "string"}},
           ["pattern", "path"]),
        fn("notes", "Record structured memory: kind=idea|fact|failure|todo.",
           {"kind": {"type": "string", "enum": ["idea", "fact", "failure", "todo"]},
            "content": {"type": "string"}}, ["kind", "content"]),
        fn("submit_flag", "REPORT a confirmed vulnerability finding. Pass a short "
           "label (e.g. 'sql-injection:/login?user=') and a writeup (type, PoC, "
           "impact). This is a pentest, NOT a CTF — there is no flag to find; "
           "report every real vulnerability you prove.",
           {"flag": {"type": "string"}, "writeup": {"type": "string"}}, ["flag"]),
        fn("finish", "End the pentest of this target. The ONLY legal way to stop.",
           {"summary": {"type": "string"}, "give_up": {"type": "boolean"}},
           ["summary"]),
    ]


def build_tools(ctx: ToolContext, cfg, minimal: bool = False) -> dict:
    """name -> callable(**args) -> str result.

    minimal=True (swarm workers): submit_flag/finish return bare results — no
    finish-gate, no early-give-up rejection, no surgical-submit nudges. Trusts
    the model (Cairn philosophy). Default False = legacy behavior unchanged."""

    def t_bash(command, timeout=120):
        r = run_bash(command, ctx.workdir,
                     timeout=min(int(timeout or cfg.bash_timeout), cfg.bash_timeout_max),
                     head_tail=cfg.head_tail)
        return (f"exit={r['exit_code']} elapsed={r['elapsed']}s\n{r['summary']}\n"
                f"[full log: {r['log_path']}]")

    def t_port_scan(host, ports="top100"):
        h = str(host).split(":")[0]
        if str(ports) in ("top100", "top-100", ""):
            parg = "--top-ports 100"
        elif str(ports) == "full":
            parg = "-p-"
        else:
            parg = f"-p {ports}"
        cmd = f"nmap -Pn -T3 --max-rate 400 {parg} {h}"
        r = run_bash(cmd, ctx.workdir, timeout=180, head_tail=cfg.head_tail)
        return (f"exit={r['exit_code']} elapsed={r['elapsed']}s\n{r['summary']}\n"
                f"[full log: {r['log_path']}]")

    def t_r2_analyze(binary, commands="aaa; afl"):
        try:
            import r2pipe
        except ImportError:
            return ("[r2_analyze] r2pipe not installed — use bash with objdump/"
                    "gdb/strings for binary analysis instead.")
        p = Path(binary)
        if not p.is_absolute():
            p = ctx.workdir / binary
        if not p.exists():
            return f"[r2_analyze] binary not found: {p}"
        try:
            r2 = r2pipe.open(str(p))
            out = r2.cmd(commands)
            r2.quit()
            return cap(out)
        except Exception as e:  # noqa: BLE001
            return f"[r2_analyze error] {type(e).__name__}: {e}"

    def t_http(url, method="GET", headers=None, body=None, follow_redirects=True):
        try:
            r = httpx.request(method, url, headers=headers or {}, content=body,
                              follow_redirects=bool(follow_redirects), timeout=30,
                              verify=False)
        except httpx.HTTPError as e:
            return f"[http error] {type(e).__name__}: {e}"
        return (f"status={r.status_code} final_url={r.url}\n"
                f"headers={dict(list(r.headers.items())[:15])}\n"
                f"body:\n{cap(r.text)}")

    def t_read(path, offset=0, limit=400):
        p = Path(path)
        if not p.is_absolute():
            p = ctx.workdir / path
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as e:
            return f"[read error] {e}"
        return cap("\n".join(lines[int(offset or 0):int(offset or 0) + int(limit or 400)]))

    def t_write(path, content):
        p = Path(path)
        if not p.is_absolute():
            p = ctx.workdir / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return f"wrote {len(content)} bytes to {p}"

    def t_list(path="."):
        p = Path(path)
        if not p.is_absolute():
            p = ctx.workdir / path
        try:
            names = sorted(f"{'d' if x.is_dir() else '-'} {x.name}"
                           for x in p.iterdir())
        except OSError as e:
            return f"[list error] {e}"
        return cap("\n".join(names) or "(empty)")

    def t_grep(pattern, path):
        p = Path(path)
        if not p.is_absolute():
            p = ctx.workdir / path
        try:
            rx = re.compile(pattern, re.IGNORECASE)
            hits = [f"{i}:{line}" for i, line in enumerate(
                p.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
                if rx.search(line)]
        except (OSError, re.error) as e:
            return f"[grep error] {e}"
        return cap("\n".join(hits) or "(no matches)")

    def t_notes(kind, content):
        # swarm: route to the Blackboard (facts → Fact, ideas → claimable Intent)
        # so findings are a shared system asset, not per-agent recall.
        if ctx.notes_sink is not None:
            return ctx.notes_sink(kind, content)
        return ctx.notes.add(kind, content)

    def t_submit(flag, writeup=""):
        flag = str(flag).strip()
        if minimal:
            # swarm: bare result, no nudges. submit_fn side-effect (last_submit)
            # is how the worker/orchestrator learns a flag landed.
            res = ctx.submit_fn(flag, str(writeup))
            ctx.last_submit = res
            if not res["correct"]:
                ctx.wrong_flags.add(flag)
            return f"correct={res['correct']} remaining={res['remaining']}"
        # (pentest build: labels are vuln names like 'sql-injection:/login?user='
        # — no CTF flag-shape check applies)
        warn = ""
        if flag in ctx.wrong_flags:
            return (warn + "this exact flag was already proven WRONG on this "
                    "challenge — do not resubmit; change approach.")
        res = ctx.submit_fn(flag, str(writeup))
        ctx.last_submit = res
        if not res["correct"]:
            ctx.wrong_flags.add(flag)
            return (warn + "incorrect — recorded as decoy/wrong; analyze WHY "
                    "(decoy cred? truncated value?) before trying variants.")
        msg = f"correct={res['correct']} remaining={res['remaining']}"
        if res["correct"] and res["remaining"] > 0:
            msg += (f" — {res['remaining']} more flag(s) on this challenge: "
                    "keep hunting (other routes/roles/params).")
        return warn + msg

    def t_finish(summary="", give_up=False):
        if minimal:
            # swarm: trust the model's call to stop — no gate, no early-give-up
            # rejection. The orchestrator's deadline is the only hard backstop.
            ctx.finished = True
            ctx.finish_summary = str(summary)
            ctx.gave_up = bool(give_up)
            return "challenge attempt finished."
        # finish-gate (#12): if submit said flags still remain, force ONE final
        # harvest/verify pass before we let the agent stop (kills "died one step
        # short" / missed multi-flag losses).
        remaining = (ctx.last_submit or {}).get("remaining")
        if (not ctx.gate_checked and not give_up and remaining
                and int(remaining) > 0):
            ctx.gate_checked = True
            return ("FINISH GATE: submit reported " + str(remaining) + " flag(s) "
                    "still REMAIN on this challenge. Before finishing, do a final "
                    "sweep: `grep -rEo 'flag\\{[^}]+\\}' /challenge /flag /app "
                    "/var/www /tmp 2>/dev/null`, check `env` and other "
                    "routes/roles/params, and submit_flag any suspects. Then call "
                    "finish again.")
        # run-6661 c-04 lesson: giving up at 5.6min with zero facts on a
        # still-booting target burned the attempt AND locked the retry gate
        # (no progress recorded). Block early give-ups that learned nothing;
        # a finish backed by facts or submits is always honored.
        if give_up and time.time() - ctx.start_ts < 300 \
                and ctx.notes.facts_count() == 0 and ctx.last_submit is None:
            return ("finish(give_up) REJECTED: under 5 minutes elapsed with no "
                    "facts and no submits recorded. The target may still be "
                    "booting (slow services need 30-90s) — re-probe with "
                    "curl/TCP, and record what you learned as notes(kind=fact "
                    "or failure) before giving up.")
        ctx.finished = True
        ctx.finish_summary = str(summary)
        ctx.gave_up = bool(give_up)
        return "challenge attempt finished."

    return {"bash": t_bash, "port_scan": t_port_scan, "r2_analyze": t_r2_analyze,
            "http_request": t_http, "read_file": t_read, "write_file": t_write,
            "list_dir": t_list, "grep": t_grep, "notes": t_notes,
            "submit_flag": t_submit, "finish": t_finish}

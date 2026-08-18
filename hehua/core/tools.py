"""Tool set: bash(+bg trio) / port_scan / r2 / http_request / file ops / grep /
notes / submit_flag(report finding) / finish."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .memory import Notes
from .sandbox import _kill_tree, _pgid_of, run_bash, spawn_bash


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
    submit_fn: object            # (label, writeup) -> dict(correct, remaining, note)
    addrs: list = field(default_factory=list)
    finished: bool = False
    finish_summary: str = ""
    gave_up: bool = False
    last_submit: dict | None = None
    start_ts: float = field(default_factory=time.time)
    # background bash tasks: id -> {"proc", "log_path", "command", "started"}
    bg_tasks: dict = field(default_factory=dict)
    # every bash session's pgid (foreground AND background, incl. `cmd &`
    # stragglers sharing the group) — the runner kills them all at run end so
    # half-built proxies/tunnels die with the session
    pgids: list = field(default_factory=list)
    # when set, the `notes` tool routes here (shared-notes sink with locking)
    # instead of Notes.add
    notes_sink: object = None


def build_schemas() -> list[dict]:
    def fn(name, desc, props, required):
        return {"type": "function", "function": {
            "name": name, "description": desc,
            "parameters": {"type": "object", "properties": props,
                           "required": required}}}
    return [
        fn("bash", "Run a shell command in the isolated workdir. Long output is "
           "spooled to a log file; you get head+tail and the log path. For "
           "long-running jobs (nmap -p-, sqlmap, hydra, long fuzzing) pass "
           "background=true — it starts immediately with NO timer and YOU "
           "decide when it's done by polling bash_status.",
           {"command": {"type": "string"},
            "timeout": {"type": "integer", "description": "foreground safety "
                       "ceiling in seconds (default 1200). Irrelevant when "
                       "background=true."},
            "background": {"type": "boolean", "description": "run as a polled "
                          "background task — no timer, model-judged lifetime"}},
           ["command"]),
        fn("bash_status", "Poll a background bash task: running (with output "
           "tail) or done (exit code + head/tail). Call repeatedly until YOU "
           "judge the task finished or doomed.",
           {"task_id": {"type": "integer"}}, ["task_id"]),
        fn("bash_kill", "Kill a background bash task (whole process group).",
           {"task_id": {"type": "integer"}}, ["task_id"]),
        fn("port_scan", "Bounded TCP port scan via nmap (ALWAYS use this, NEVER a "
           "bash /dev/tcp loop which spawns runaway jobs). host=IP or IP:port; "
           "ports='top100' | '1-1000' | 'full' | '22,80,443'.",
           {"host": {"type": "string"}, "ports": {"type": "string"}},
           ["host"]),
        fn("r2_analyze", "Run radare2 commands on a binary for reverse engineering "
           "(decompile, list functions, find strings, control-flow graph). You "
           "generate r2 commands; the tool executes them and returns structured "
           "output. Examples: 'aaa; afl' (analyze+list funcs), 'pdf @main' "
           "(decompile main), 'iz~secret' (search strings), 'axt @sym' "
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
        fn("notes", "Record structured memory. kinds: fact (raw observation "
           "+ your reading, e.g. 'GET /admin -> 403 role=guest: needs auth'), "
           "failure (ruled-out angle + why), idea (hypothesis), claim "
           "(lane you are taking now — parallel agents avoid duplicating it), "
           "fork (divergence between entries: state changed or interpretations "
           "differ — an OPPORTUNITY: find what caused the change).",
           {"kind": {"type": "string",
                     "enum": ["idea", "fact", "failure", "todo", "claim", "fork"]},
            "content": {"type": "string"}}, ["kind", "content"]),
        fn("submit_flag", "REPORT a confirmed vulnerability finding. Pass a short "
           "label (e.g. 'sql-injection:/login?user=') and a writeup (type, PoC, "
           "impact). This is a pentest, NOT a CTF — there is no flag to find; "
           "report every real vulnerability you prove.",
           {"flag": {"type": "string"}, "writeup": {"type": "string"}}, ["flag"]),
        fn("finish", "End the pentest of this target. The ONLY legal way to stop.",
           {"summary": {"type": "string"},
            "give_up": {"type": "boolean"}},
           ["summary"]),
    ]


def _infra_note(ctx, line: str) -> None:
    """Append infrastructure state to INFRA.md — the shared persistent record
    of background tasks (proxies/tunnels/scans): PARALLEL models read it to
    reuse instead of rebuild; the report reads it to find logs, and the run
    end reaps everything."""
    try:
        with open(Path(ctx.workdir) / "INFRA.md", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {line}\n")
    except OSError:
        pass


def build_tools(ctx: ToolContext, cfg) -> dict:
    """name -> callable(**args) -> str result."""

    def t_bash(command, timeout=None, background=False):
        """background=True: no timer at all — the model polls bash_status /
        kills via bash_kill when IT judges the task done/doomed. Foreground
        keeps only a generous safety ceiling (1200s) so a wedged command
        can't eat the whole session silently."""
        if background:
            info = spawn_bash(command, ctx.workdir)
            if "error" in info:
                return info["error"]
            tid = len(ctx.bg_tasks) + 1
            ctx.bg_tasks[tid] = {"proc": info["proc"],
                                 "log_path": info["log_path"],
                                 "command": command,
                                 "started": time.time()}
            ctx.pgids.append(_pgid_of(info["proc"].pid))
            _infra_note(ctx, f"bg task {tid} START: {command[:140]} "
                             f"| log: {info['log_path']}")
            return (f"[bg task {tid} started] log: {info['log_path']}\n"
                    f"Poll with bash_status({tid}); kill with bash_kill({tid}). "
                    f"Recorded in INFRA.md so parallel models can reuse it. "
                    f"The task survives this tool call — keep working and check "
                    f"back, or poll repeatedly until YOU decide it's done.")
        to = int(timeout) if timeout else cfg.bash_timeout_max
        to = min(to, cfg.bash_timeout_max)
        r = run_bash(command, ctx.workdir, timeout=to,
                     head_tail=cfg.head_tail, pgid_sink=ctx.pgids.append)
        return (f"exit={r['exit_code']} elapsed={r['elapsed']}s\n{r['summary']}\n"
                f"[full log: {r['log_path']}]")

    def t_bash_status(task_id):
        t = ctx.bg_tasks.get(int(task_id))
        if t is None:
            return f"[bg] no such task: {task_id}"
        rc = t["proc"].poll()
        elapsed = round(time.time() - t["started"], 1)
        try:
            out = Path(t["log_path"]).read_text(encoding="utf-8",
                                                errors="replace")
        except OSError:
            out = ""
        if rc is None:
            tail = out[-cfg.head_tail:] if out else "(no output yet)"
            return (f"[bg task {task_id} RUNNING {elapsed}s]\n$ {t['command']}\n"
                    f"...tail...\n{tail}\n"
                    f"[still running — poll again, or bash_kill if you judge "
                    f"it doomed]")
        headtail = (out if len(out) <= cfg.head_tail * 2
                    else out[:cfg.head_tail] + "\n...\n" + out[-cfg.head_tail:])
        _infra_note(ctx, f"bg task {task_id} DONE exit={rc} ({elapsed}s): "
                         f"{t['command'][:100]}")
        return (f"[bg task {task_id} DONE {elapsed}s exit={rc}]\n$ {t['command']}\n"
                f"{headtail}\n[full log: {t['log_path']}]")

    def t_bash_kill(task_id):
        t = ctx.bg_tasks.get(int(task_id))
        if t is None:
            return f"[bg] no such task: {task_id}"
        _kill_tree(t["proc"].pid)
        _infra_note(ctx, f"bg task {task_id} KILLED: {t['command'][:100]}")
        return f"[bg task {task_id} killed]"

    def t_port_scan(host, ports="top100"):
        h = str(host).split(":")[0]
        if str(ports) in ("top100", "top-100", ""):
            parg = "--top-ports 100"
        elif str(ports) == "full":
            parg = "-p-"
        else:
            parg = f"-p {ports}"
        cmd = f"nmap -Pn -T3 --max-rate 400 {parg} {h}"
        if "-p-" in parg:
            # full sweep takes minutes — no fixed timer, run as a polled bg
            # task (the model decides when it's done; old 180s cut killed
            # scans mid-sweep)
            info = spawn_bash(cmd, ctx.workdir)
            if "error" in info:
                return info["error"]
            tid = len(ctx.bg_tasks) + 1
            ctx.bg_tasks[tid] = {"proc": info["proc"],
                                 "log_path": info["log_path"],
                                 "command": cmd,
                                 "started": time.time()}
            _infra_note(ctx, f"bg task {tid} START: nmap full sweep of {h} "
                             f"| log: {info['log_path']}")
            return (f"[bg task {tid} started: nmap full sweep of {h}] "
                    f"log: {info['log_path']}\nPoll bash_status({tid}) until "
                    f"done — keep attacking other angles meanwhile.")
        r = run_bash(cmd, ctx.workdir, timeout=1200, head_tail=cfg.head_tail)
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
                              follow_redirects=bool(follow_redirects), timeout=60,
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
        if ctx.notes_sink is not None:
            return ctx.notes_sink(kind, content)
        return ctx.notes.add(kind, content)

    def t_submit(flag, writeup=""):
        label = str(flag).strip()
        res = ctx.submit_fn(label, str(writeup))
        ctx.last_submit = res
        if res.get("note"):
            return ("[duplicate] " + res["note"] +
                    " — refine the label/writeup, or hunt a DIFFERENT issue.")
        return (f"✔ finding recorded: {label}\n"
                "Real applications usually hold several issues and deeper "
                "access reveals more — keep hunting (other routes/roles/"
                "params/upgrades).")

    def t_finish(summary="", give_up=False):
        # light give-up gate: an agent that neither worked the target nor
        # recorded anything new learned nothing. Reject give-ups that are
        # BOTH under 8 minutes AND have <2 recorded facts; any finish backed
        # by findings/notes, or on budget, is honored. A bare finish() with
        # NO submits and NO intel is a give-up in disguise — gate it
        # identically (else the model sidesteps via finish(give_up=False)
        # after learning nothing).
        intel = sum(1 for e in ctx.notes.entries
                    if e.get("kind") in ("fact", "failure"))
        premature = give_up or (ctx.last_submit is None and intel < 2)
        if (premature and time.time() - ctx.start_ts < 480
                and intel < 2):
            return ("finish REJECTED: under 8 minutes elapsed "
                    "with fewer than 2 new facts recorded. Out of ideas? "
                    "FIRST read the other models' NOTES_*.md files — a "
                    "divergent sibling result is a new lead, not a "
                    "dead end. If you truly exhausted this angle, "
                    "notes(kind='fact' or 'failure') WHAT you ruled out "
                    "and why. Otherwise keep attacking — try a different "
                    "tool, parameter, role, or attack class. Then call "
                    "finish again.")
        ctx.finished = True
        ctx.finish_summary = str(summary)
        ctx.gave_up = bool(give_up)
        return "pentest of this target finished."

    return {"bash": t_bash, "bash_status": t_bash_status, "bash_kill": t_bash_kill,
            "port_scan": t_port_scan, "r2_analyze": t_r2_analyze,
            "http_request": t_http, "read_file": t_read, "write_file": t_write,
            "list_dir": t_list, "grep": t_grep, "notes": t_notes,
            "submit_flag": t_submit, "finish": t_finish}

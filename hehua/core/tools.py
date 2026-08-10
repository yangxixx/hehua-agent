from __future__ import annotations
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
import httpx
from .memory import Notes
from .sandbox import run_bash

def cap(text: str, max_bytes: int=8192) -> str:
    if len(text) <= max_bytes:
        return text
    h = max_bytes // 2
    return text[:h] + f'\n... [truncated {len(text)} chars] ...\n' + text[-h:]

@dataclass
class ToolContext:
    workdir: Path
    notes: Notes
    submit_fn: object
    addrs: list = field(default_factory=list)
    finished: bool = False
    finish_summary: str = ''
    gave_up: bool = False
    last_submit: dict | None = None
    wrong_flags: set = field(default_factory=set)
    start_ts: float = field(default_factory=time.time)
    gate_checked: bool = False

def build_schemas() -> list[dict]:

    def fn(name, desc, props, required):
        return {'type': 'function', 'function': {'name': name, 'description': desc, 'parameters': {'type': 'object', 'properties': props, 'required': required}}}
    return [fn('bash', 'Run a shell command in the isolated workdir. Long output is spooled to a log file; you get head+tail and the log path.', {'command': {'type': 'string'}, 'timeout': {'type': 'integer', 'description': 'seconds, max 300'}}, ['command']), fn('port_scan', "Bounded TCP port scan via nmap (ALWAYS use this, NEVER a bash /dev/tcp loop which spawns runaway jobs). host=IP or IP:port; ports='top100' | '1-1000' | 'full' | '22,80,443'.", {'host': {'type': 'string'}, 'ports': {'type': 'string'}}, ['host']), fn('http_request', 'Send an HTTP request; returns status, final URL, headers and (capped) body.', {'method': {'type': 'string'}, 'url': {'type': 'string'}, 'headers': {'type': 'object'}, 'body': {'type': 'string'}, 'follow_redirects': {'type': 'boolean'}}, ['url']), fn('read_file', 'Read a file (offset/limit in lines).', {'path': {'type': 'string'}, 'offset': {'type': 'integer'}, 'limit': {'type': 'integer'}}, ['path']), fn('write_file', 'Write a file (exploit scripts, payload lists, ...).', {'path': {'type': 'string'}, 'content': {'type': 'string'}}, ['path', 'content']), fn('list_dir', 'List a directory.', {'path': {'type': 'string'}}, ['path']), fn('grep', 'Regex-search a file for patterns (returns matching lines).', {'pattern': {'type': 'string'}, 'path': {'type': 'string'}}, ['pattern', 'path']), fn('notes', 'Record structured memory: kind=idea|fact|failure|todo.', {'kind': {'type': 'string', 'enum': ['idea', 'fact', 'failure', 'todo']}, 'content': {'type': 'string'}}, ['kind', 'content']), fn('submit_flag', 'Submit a candidate flag. Idempotent; wrong submits are not penalized. Returns whether correct and flags remaining.', {'flag': {'type': 'string'}, 'writeup': {'type': 'string'}}, ['flag']), fn('finish', 'End the attempt on this challenge. The ONLY legal way to stop.', {'summary': {'type': 'string'}, 'give_up': {'type': 'boolean'}}, ['summary'])]

def build_tools(ctx: ToolContext, cfg) -> dict:

    def t_bash(command, timeout=120):
        r = run_bash(command, ctx.workdir, timeout=min(int(timeout or cfg.bash_timeout), cfg.bash_timeout_max), head_tail=cfg.head_tail)
        return f"exit={r['exit_code']} elapsed={r['elapsed']}s\n{r['summary']}\n[full log: {r['log_path']}]"

    def t_port_scan(host, ports='top100'):
        h = str(host).split(':')[0]
        if str(ports) in ('top100', 'top-100', ''):
            parg = '--top-ports 100'
        elif str(ports) == 'full':
            parg = '-p-'
        else:
            parg = f'-p {ports}'
        cmd = f'nmap -Pn -T3 --max-rate 400 {parg} {h}'
        r = run_bash(cmd, ctx.workdir, timeout=180, head_tail=cfg.head_tail)
        return f"exit={r['exit_code']} elapsed={r['elapsed']}s\n{r['summary']}\n[full log: {r['log_path']}]"

    def t_http(url, method='GET', headers=None, body=None, follow_redirects=True):
        try:
            r = httpx.request(method, url, headers=headers or {}, content=body, follow_redirects=bool(follow_redirects), timeout=30, verify=False)
        except httpx.HTTPError as e:
            return f'[http error] {type(e).__name__}: {e}'
        return f'status={r.status_code} final_url={r.url}\nheaders={dict(list(r.headers.items())[:15])}\nbody:\n{cap(r.text)}'

    def t_read(path, offset=0, limit=400):
        p = Path(path)
        if not p.is_absolute():
            p = ctx.workdir / path
        try:
            lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError as e:
            return f'[read error] {e}'
        return cap('\n'.join(lines[int(offset or 0):int(offset or 0) + int(limit or 400)]))

    def t_write(path, content):
        p = Path(path)
        if not p.is_absolute():
            p = ctx.workdir / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding='utf-8')
        return f'wrote {len(content)} bytes to {p}'

    def t_list(path='.'):
        p = Path(path)
        if not p.is_absolute():
            p = ctx.workdir / path
        try:
            names = sorted((f"{('d' if x.is_dir() else '-')} {x.name}" for x in p.iterdir()))
        except OSError as e:
            return f'[list error] {e}'
        return cap('\n'.join(names) or '(empty)')

    def t_grep(pattern, path):
        p = Path(path)
        if not p.is_absolute():
            p = ctx.workdir / path
        try:
            rx = re.compile(pattern, re.IGNORECASE)
            hits = [f'{i}:{line}' for i, line in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(), 1) if rx.search(line)]
        except (OSError, re.error) as e:
            return f'[grep error] {e}'
        return cap('\n'.join(hits) or '(no matches)')

    def t_notes(kind, content):
        return ctx.notes.add(kind, content)

    def t_submit(flag, writeup=''):
        flag = str(flag).strip()
        if flag in ctx.wrong_flags:
            return 'this exact flag was already proven WRONG on this challenge — do not resubmit; change approach.'
        res = ctx.submit_fn(flag, str(writeup))
        ctx.last_submit = res
        if not res['correct']:
            ctx.wrong_flags.add(flag)
            return 'incorrect — recorded as decoy/wrong; analyze WHY (decoy cred? truncated value?) before trying variants.'
        msg = f"correct={res['correct']} remaining={res['remaining']}"
        if res['correct'] and res['remaining'] > 0:
            msg += f" — {res['remaining']} more flag(s) on this challenge: keep hunting (other routes/roles/params)."
        return msg

    def t_finish(summary='', give_up=False):
        remaining = (ctx.last_submit or {}).get('remaining')
        if not ctx.gate_checked and (not give_up) and remaining and (int(remaining) > 0):
            ctx.gate_checked = True
            return 'FINISH GATE: submit reported ' + str(remaining) + " flag(s) still REMAIN on this challenge. Before finishing, do a final sweep: `grep -rEo 'flag\\{[^}]+\\}' /challenge /flag /app /var/www /tmp 2>/dev/null`, check `env` and other routes/roles/params, and submit_flag any suspects. Then call finish again."
        if give_up and time.time() - ctx.start_ts < 300 and (ctx.notes.facts_count() == 0) and (ctx.last_submit is None):
            return 'finish(give_up) REJECTED: under 5 minutes elapsed with no facts and no submits recorded. The target may still be booting (slow services need 30-90s) — re-probe with curl/TCP, and record what you learned as notes(kind=fact or failure) before giving up.'
        ctx.finished = True
        ctx.finish_summary = str(summary)
        ctx.gave_up = bool(give_up)
        return 'challenge attempt finished.'
    return {'bash': t_bash, 'port_scan': t_port_scan, 'http_request': t_http, 'read_file': t_read, 'write_file': t_write, 'list_dir': t_list, 'grep': t_grep, 'notes': t_notes, 'submit_flag': t_submit, 'finish': t_finish}

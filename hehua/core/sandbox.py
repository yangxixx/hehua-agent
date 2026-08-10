from __future__ import annotations
import os
import shutil
import subprocess
import time
from pathlib import Path
_BASH = shutil.which('bash')

def run_bash(command: str, workdir: str | Path, timeout: int=120, head_tail: int=4096) -> dict:
    workdir = Path(workdir)
    outdir = workdir / 'out'
    outdir.mkdir(parents=True, exist_ok=True)
    n = len(list(outdir.glob('bash_*.log'))) + 1
    log = outdir / f'bash_{n:03d}.log'
    start = time.time()
    code = -1
    argv = [_BASH, '-c', command] if _BASH else None
    import os as _os
    env = dict(_os.environ)
    env.setdefault('HEHUA_ROOT', str(Path(__file__).resolve().parents[2]))
    try:
        with open(log, 'wb') as f:
            p = subprocess.Popen(argv if argv else command, shell=argv is None, cwd=workdir, stdout=f, stderr=f, stdin=subprocess.DEVNULL, env=env, start_new_session=True)
            try:
                code = p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_tree(p.pid)
                f.write(f'\n[killed: timeout after {timeout}s]'.encode())
    except OSError as e:
        log.write_text(f'[spawn error] {e}', encoding='utf-8')
    out = log.read_text(encoding='utf-8', errors='replace')
    return {'exit_code': code, 'log_path': str(log), 'summary': _head_tail(out, head_tail, str(log)), 'elapsed': round(time.time() - start, 1)}

def _kill_tree(pid: int) -> None:
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(pid)], capture_output=True, timeout=10)
        else:
            try:
                os.killpg(os.getpgid(pid), 9)
            except ProcessLookupError:
                pass
            else:
                return
            os.kill(pid, 9)
    except OSError:
        pass

def _head_tail(text: str, size: int, log_path: str) -> str:
    if len(text) <= size * 2:
        return text
    return text[:size] + f'\n\n... [output truncated: {len(text)} bytes total; full log at {log_path} — use read_file/grep to inspect] ...\n\n' + text[-size:]

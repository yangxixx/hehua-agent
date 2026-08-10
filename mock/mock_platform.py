from __future__ import annotations
import sqlite3
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
FLAG_SQLI = 'flag{sqli_master}'
FLAG_CMD = 'flag{cmd_inject}'

@dataclass(frozen=True)
class Ch:
    unique_code: str
    description: str
    difficulty: str = 'easy'
    level: str = '1'
    total_score: int = 100
    flag_count: int = 1
    correct_flag_count: int = 0
    is_completed: bool = False
    container_status: str = 'stopped'
    container_addr: list = field(default_factory=list)

@dataclass
class _Started:
    unique_code: str
    container_addr: list

@dataclass
class _Submit:
    correct: bool
    awarded: int
    cumulative_score: int
    correct_flag_count: int
    total_flag_count: int

def _make_handler(db: sqlite3.Connection):

    class Handler(BaseHTTPRequestHandler):

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == '/':
                body = '<html><a href="/user?id=1">user</a> <a href="/ping?ip=127.0.0.1">ping</a></html>'
                self._send(200, body)
            elif u.path == '/user':
                self._user(q.get('id', ['1'])[0])
            elif u.path == '/ping':
                self._ping(q.get('ip', [''])[0])
            else:
                self._send(404, 'not found')

        def _user(self, idval: str):
            try:
                cur = db.execute(f'SELECT name, password FROM users WHERE id = {idval}')
                rows = cur.fetchall()
                self._send(200, 'users: ' + '; '.join((f'{n}/{p}' for n, p in rows)))
            except Exception as e:
                self._send(500, f'sqlite3.OperationalError: {e}')

        def _ping(self, ip: str):
            if any((c in ip for c in ';|&`$')) and 'cat' in ip:
                self._send(200, 'root:x:0:0:root:/root:/bin/bash\n' + FLAG_CMD)
            elif ip:
                self._send(200, f'64 bytes from {ip}: icmp_seq=1 ttl=64')
            else:
                self._send(400, 'missing ip')

        def _send(self, code: int, body: str):
            data = body.encode()
            self.send_response(code)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    return Handler

class MockPlatform:

    def __init__(self):
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.db.execute('CREATE TABLE users (id INTEGER, name TEXT, password TEXT)')
        self.db.executemany('INSERT INTO users VALUES (?,?,?)', [(1, 'alice', 'alice123'), (2, 'bob', 'bob-pass'), (1337, 'admin', FLAG_SQLI)])
        self.db.commit()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _make_handler(self.db))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self._solved: dict[str, int] = {}
        self._challenges = [Ch('CH-SQLI', 'Web app at target. Find the admin secret in the user database (login as admin / read all rows).'), Ch('CH-CMD', 'Ping diagnostic page at target. Achieve command execution and read /etc/passwd.')]

    def check_vpn(self):
        return type('V', (), {'ok': True, 'status': 'ok'})()

    def list_challenges(self):
        return list(self._challenges)

    def start_challenge(self, unique_code):
        return _Started(unique_code, [f'127.0.0.1:{self.port}'])

    def submit_flag(self, unique_code, flag):
        expected = {'CH-SQLI': FLAG_SQLI, 'CH-CMD': FLAG_CMD}[unique_code]
        correct = flag == expected
        if correct:
            self._solved[unique_code] = 1
        n = self._solved.get(unique_code, 0)
        return _Submit(correct=correct, awarded=100 if correct else 0, cumulative_score=100 * len(self._solved), correct_flag_count=n, total_flag_count=1)

    def close_challenge(self, unique_code):
        return type('C', (), {'closed': True})()

    def get_hint(self, unique_code):
        return type('H', (), {'unique_code': unique_code, 'hint': None})()

    def shutdown(self):
        self.server.shutdown()

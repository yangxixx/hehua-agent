from __future__ import annotations
import json
import random
import time
import httpx
from .client import ChatResult, ContextOverflow, QuotaExhausted, ToolCall
ANTHROPIC_URL = 'https://open.bigmodel.cn/api/anthropic/v1/messages'
ANTHROPIC_VERSION = '2023-06-01'
_RETRYABLE_STATUS = {500, 502, 503, 529}
_MAX_ATTEMPTS = 3
_RATE_LIMIT_MAX = 6

class AnthropicGLMClient:

    def __init__(self, api_key: str, model: str='glm-5.2', budget=None, base_url: str=ANTHROPIC_URL, timeout: float=180.0):
        self.api_key = api_key
        self.model = model
        self.budget = budget
        self.exhausted = False
        self.url = base_url
        self.timeout = timeout

    def set_challenge(self, code: str) -> None:
        pass

    def chat(self, messages: list[dict], tools: list[dict] | None=None, model_role: str='primary', temperature: float=0.3, thinking: str | None=None) -> ChatResult:
        if self.exhausted:
            raise QuotaExhausted('glm anthropic: quota already marked exhausted')
        system, conv = self._split_system(messages)
        body = self._build_body(system, conv, tools, temperature, thinking)
        data = self._post(body)
        return self._parse(data)

    def _split_system(self, messages):
        parts, conv = ([], [])
        for m in messages:
            if m.get('role') == 'system':
                c = m.get('content')
                if isinstance(c, list):
                    c = ' '.join((b.get('text', '') for b in c if isinstance(b, dict) and b.get('type') == 'text'))
                if c:
                    parts.append(str(c))
            else:
                conv.append(m)
        return ('\n\n'.join(parts) if parts else None, conv)

    def _build_body(self, system, conv, tools, temperature, thinking):
        body = {'model': self.model, 'max_tokens': 16000, 'messages': self._translate_conv(conv), 'temperature': temperature}
        if system:
            body['system'] = system
        if thinking == 'on':
            body['thinking'] = {'type': 'enabled', 'budget_tokens': 4096}
        if tools:
            body['tools'] = [{'name': t['function']['name'], 'description': t['function'].get('description', ''), 'input_schema': t['function'].get('parameters', {'type': 'object', 'properties': {}})} for t in tools]
        return body

    def _translate_conv(self, conv):
        out, i, n = ([], 0, len(conv))
        while i < n:
            m = conv[i]
            role = m.get('role')
            if role == 'user':
                out.append({'role': 'user', 'content': self._user_text(m.get('content'))})
                i += 1
            elif role == 'assistant':
                blocks = []
                if m.get('content'):
                    blocks.append({'type': 'text', 'text': str(m['content'])})
                for tc in m.get('tool_calls') or []:
                    fn = tc.get('function', {})
                    args = fn.get('arguments', '{}')
                    if isinstance(args, str):
                        try:
                            args = json.loads(args or '{}')
                        except json.JSONDecodeError:
                            args = {}
                    blocks.append({'type': 'tool_use', 'id': tc.get('id', ''), 'name': fn.get('name', ''), 'input': args})
                out.append({'role': 'assistant', 'content': blocks or [{'type': 'text', 'text': ' '}]})
                i += 1
            elif role == 'tool':
                content = []
                while i < n and conv[i].get('role') == 'tool':
                    content.append({'type': 'tool_result', 'tool_use_id': conv[i].get('tool_call_id', ''), 'content': str(conv[i].get('content', ''))})
                    i += 1
                if i < n and conv[i].get('role') == 'user':
                    content.append({'type': 'text', 'text': self._user_text(conv[i].get('content'))})
                    i += 1
                out.append({'role': 'user', 'content': content})
            else:
                i += 1
        return self._enforce_alternation(out)

    @staticmethod
    def _user_text(content):
        if isinstance(content, list):
            return ' '.join((b.get('text', '') for b in content if isinstance(b, dict) and b.get('type') == 'text'))
        return str(content or '')

    @staticmethod
    def _enforce_alternation(msgs):
        if not msgs:
            return [{'role': 'user', 'content': '.'}]
        merged = []
        for m in msgs:
            if merged and merged[-1]['role'] == m['role']:
                merged[-1]['content'] = AnthropicGLMClient._concat(merged[-1]['content'], m['content'])
            else:
                merged.append({'role': m['role'], 'content': m['content']})
        if merged[0]['role'] != 'user':
            merged.insert(0, {'role': 'user', 'content': '.'})
        return merged

    @staticmethod
    def _concat(a, b):

        def to_blocks(x):
            return x if isinstance(x, list) else [{'type': 'text', 'text': str(x)}]
        return to_blocks(a) + to_blocks(b)

    def _post(self, body):
        attempt = rate = 0
        while True:
            attempt += 1
            try:
                resp = httpx.post(self.url, headers={'x-api-key': self.api_key, 'anthropic-version': ANTHROPIC_VERSION, 'Content-Type': 'application/json'}, json=body, timeout=self.timeout)
            except httpx.HTTPError:
                if attempt >= _MAX_ATTEMPTS:
                    raise RuntimeError('glm anthropic: network error after retries')
                time.sleep(2 ** attempt + random.random())
                continue
            if resp.status_code == 429:
                txt = resp.text or ''
                if any((s in txt for s in ('1113', '余额', 'insufficient', 'balance'))):
                    self.exhausted = True
                    raise QuotaExhausted(f'glm anthropic balance exhausted: {txt[:120]}')
                rate += 1
                if rate > _RATE_LIMIT_MAX:
                    raise RuntimeError(f'glm anthropic 429 after {rate} waits: {txt[:120]}')
                time.sleep(min(90.0, 15.0 * rate) + random.random())
                attempt -= 1
                continue
            if resp.status_code in _RETRYABLE_STATUS:
                if attempt >= _MAX_ATTEMPTS:
                    raise RuntimeError(f'glm anthropic {resp.status_code}: {resp.text[:160]}')
                time.sleep(2 ** attempt + random.random())
                continue
            if resp.status_code == 400:
                low = resp.text.lower()
                if any((k in low for k in ('context', 'too long', 'token', 'length'))):
                    raise ContextOverflow(resp.text[:300])
                raise RuntimeError(f'glm anthropic 400: {resp.text[:300]}')
            if resp.status_code != 200:
                raise RuntimeError(f'glm anthropic {resp.status_code}: {resp.text[:200]}')
            return resp.json()

    def _parse(self, data):
        blocks = data.get('content') or []
        text = ''.join((b.get('text', '') for b in blocks if isinstance(b, dict) and b.get('type') == 'text'))
        calls = [ToolCall(id=b.get('id', ''), name=b.get('name', ''), arguments=b.get('input') or {}) for b in blocks if isinstance(b, dict) and b.get('type') == 'tool_use']
        u = data.get('usage') or {}
        in_tok, out_tok = (u.get('input_tokens', 0), u.get('output_tokens', 0))
        if self.budget is not None:
            self.budget.record(data.get('model', self.model), in_tok, out_tok)
        return ChatResult(content=text, tool_calls=calls, usage={'prompt_tokens': in_tok, 'completion_tokens': out_tok, 'total_tokens': in_tok + out_tok, 'cache_read_input_tokens': u.get('cache_read_input_tokens', 0)}, model=data.get('model', self.model))

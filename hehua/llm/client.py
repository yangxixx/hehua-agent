"""Minimal OpenAI-compatible chat client over httpx.

Hand-rolled (not the openai SDK) because gateway rewriting, timeouts and
failover across providers need full control over URL/headers/retries.
"""
from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import dataclass, field

import httpx

from ..gateway import rewrite_for_gateway
from .budget import Budget
from .registry import Provider


class ContextOverflow(Exception):
    """Provider rejected the prompt as too long -> caller should compact."""


class LLMUnavailable(Exception):
    """All providers exhausted."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class ChatResult:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict = field(default_factory=dict)
    model: str = ""


_RETRYABLE_STATUS = {408, 429, 500, 502, 503, 529}
_MAX_ATTEMPTS = 3


class LLMClient:
    def __init__(self, providers: list[Provider], budget: Budget | None = None,
                 gateway: bool = False, timeout: float = 180.0):
        self.budget = budget or Budget()
        self.timeout = timeout
        self._lock = threading.Lock()
        self.providers: list[Provider] = []
        for p in providers:
            if not p.usable:
                continue
            base = rewrite_for_gateway(p.base_url) if gateway else p.base_url
            self.providers.append(Provider(p.name, base, p.api_key, p.model,
                                           p.compact_model))
        self._idx = 0

    # -- public ------------------------------------------------------------
    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             model_role: str = "primary", temperature: float = 0.3,
             thinking: str | None = None) -> ChatResult:
        if not self.providers:
            raise LLMUnavailable("no LLM provider configured (missing API keys)")
        last_err: Exception | None = None
        for _ in range(len(self.providers)):
            provider = self.providers[self._idx]
            try:
                return self._call(provider, messages, tools, model_role,
                                  temperature, thinking)
            except ContextOverflow:
                raise
            except Exception as e:  # noqa: BLE001 - provider-level failover
                last_err = e
                with self._lock:
                    self._idx = (self._idx + 1) % len(self.providers)
        raise LLMUnavailable(f"all providers failed; last error: {last_err}")

    # -- internals ---------------------------------------------------------
    def _model_for(self, provider: Provider, role: str) -> str:
        if role == "compact" and provider.compact_model:
            return provider.compact_model
        return provider.model

    def _call(self, provider: Provider, messages: list[dict],
              tools: list[dict] | None, model_role: str,
              temperature: float, thinking: str | None = None) -> ChatResult:
        url = provider.base_url.rstrip("/") + "/chat/completions"
        body: dict = {
            "model": self._model_for(provider, model_role),
            "messages": messages,
            "temperature": temperature,
        }
        if thinking == "off":
            body["thinking"] = {"type": "disabled"}
        elif thinking == "on":
            body["thinking"] = {"type": "enabled"}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = httpx.post(
                    url,
                    headers={"Authorization": f"Bearer {provider.api_key}",
                             "Content-Type": "application/json"},
                    json=body, timeout=self.timeout)
            except httpx.HTTPError as e:
                if attempt >= _MAX_ATTEMPTS:
                    raise
                self._backoff(attempt)
                continue
            if resp.status_code in _RETRYABLE_STATUS:
                if attempt >= _MAX_ATTEMPTS:
                    raise RuntimeError(
                        f"{provider.name} HTTP {resp.status_code}: {resp.text[:200]}")
                self._backoff(attempt)
                continue
            if resp.status_code == 400:
                text = resp.text.lower()
                if "context" in text or "length" in text or "token" in text:
                    raise ContextOverflow(resp.text[:300])
                raise RuntimeError(f"{provider.name} HTTP 400: {resp.text[:300]}")
            if resp.status_code != 200:
                raise RuntimeError(
                    f"{provider.name} HTTP {resp.status_code}: {resp.text[:200]}")
            return self._parse(provider, resp.json())

    def _parse(self, provider: Provider, data: dict) -> ChatResult:
        msg = data["choices"][0]["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(id=tc.get("id", ""), name=tc["function"]["name"],
                                  arguments=args))
        usage = data.get("usage") or {}
        self.budget.record(data.get("model", provider.model),
                           usage.get("prompt_tokens", 0),
                           usage.get("completion_tokens", 0))
        return ChatResult(content=msg.get("content") or "", tool_calls=calls,
                          usage=usage, model=data.get("model", provider.model))

    @staticmethod
    def _backoff(attempt: int) -> None:
        time.sleep(min(30.0, (2 ** attempt) + random.random()))

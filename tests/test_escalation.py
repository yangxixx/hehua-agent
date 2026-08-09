"""Escalation: challenges flash cannot solve are handed to the GLM worker.

Offline: the real GLM client is monkeypatched to a scripted MockLLM, and the
flash worker uses a deliberately-failing LLM, so we assert the hand-off itself.
"""
from pathlib import Path

import pytest

from hehua.config import Config
from hehua.llm.budget import Budget
from hehua.llm.client import ChatResult, ToolCall
from hehua.metrics.logger import EventLogger
from hehua.orchestrate import runner
from hehua.orchestrate.state import SOLVED, State
from mock.mock_llm import MockLLM
from mock.mock_platform import MockPlatform


class FailingFlashLLM:
    """Always records one fact then gives up — never submits a flag."""

    def __init__(self):
        self.budget = Budget()

    def chat(self, messages, tools=None, model_role="primary", temperature=0.3,
             thinking=None, **kw):
        return ChatResult(content="", model="fail", tool_calls=[
            ToolCall(id="n1", name="notes",
                     arguments={"kind": "fact", "content": "no vuln found"}),
            ToolCall(id="f1", name="finish",
                     arguments={"summary": "stuck", "give_up": True}),
        ])


def test_flash_failure_escalates_to_glm(tmp_path, monkeypatch):
    # the "GLM" worker is a scripted solver (stands in for glm-5.2)
    monkeypatch.setattr(runner, "_build_esc_llm",
                        lambda cfg, budget: MockLLM())
    cfg = Config(mock_llm=False, glm_api_key="dummy")  # non-mock => esc allowed
    platform = MockPlatform()
    events = EventLogger(str(tmp_path / "events.jsonl"))
    state = State(path=tmp_path / "state.json")

    runner.run(cfg, platform, FailingFlashLLM(), events, state,
               workdir_root=str(tmp_path / "out"))

    # both mock challenges must end solved — by the GLM worker, since flash
    # always gave up. Proves the escalation hand-off works end to end.
    for code in ("CH-SQLI", "CH-CMD"):
        assert state.get(code).status == SOLVED, f"{code} not solved via GLM"
    platform.shutdown()


def test_no_glm_key_disables_escalation(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_build_esc_llm",
                        lambda cfg, budget: None if not cfg.glm_api_key else MockLLM())
    cfg = Config(mock_llm=False, glm_api_key="")  # empty key => no escalation
    assert runner._build_esc_llm(cfg, Budget()) is None

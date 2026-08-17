"""The agentic LLM attacker's plumbing, tested without a live model.

The model's *decisions* need Ollama and are exercised by an integration run, but
the request mapping, id parsing and response-joining are deterministic and must
be correct regardless -- a bug there would silently mis-measure every session.
A stub model also lets us prove the loop actually follows what it reads, which is
the whole point of the tool.
"""
from __future__ import annotations

import random

import pytest

from tools import llm_agent_attacker as la


class _FakeHTTP:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    def get(self, path, params=None, **kw):
        self.calls.append(("GET", path, params or {}))
        return _Resp(200, f"body of {path}")

    def post(self, path, data=None, **kw):
        self.calls.append(("POST", path, data or {}))
        return _Resp(200, "login result")

    def close(self):
        pass


class _Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


@pytest.mark.parametrize("arg,expected", [
    ("7", 7), ("id 12", 12), ("/records/4", 4), ("", 1), ("none", 1),
])
def test_int_extraction(arg, expected):
    assert la._int(arg) == expected


def test_perform_maps_each_tool_to_the_right_request():
    h = _FakeHTTP()
    la._perform(h, "search", "laptop'")
    la._perform(h, "view_profile", "9")
    la._perform(h, "view_record", "3")
    la._perform(h, "api_profile", "5")
    la._perform(h, "login", "admin:hunter2")
    la._perform(h, "raw", "/auth/legacy/verify_abc")
    assert h.calls == [
        ("GET", "/search", {"q": "laptop'"}),
        ("GET", "/profile/9", {}),
        ("GET", "/records/3", {}),
        ("GET", "/api/profile/5", {}),
        ("POST", "/login", {"username": "admin", "password": "hunter2"}),
        ("GET", "/auth/legacy/verify_abc", {}),
    ]


def test_raw_path_gets_a_leading_slash():
    h = _FakeHTTP()
    la._perform(h, "raw", "robots.txt")
    assert h.calls[-1] == ("GET", "/robots.txt", {})


def test_truncate_keeps_the_head_where_probes_live():
    body = "ERROR near acct_shadow_x" + ("y" * 5000)
    out = la._truncate(body, limit=100)
    assert out.startswith("ERROR near acct_shadow_x")
    assert "[truncated]" in out
    assert len(out) < 200


class _StubLLM:
    """A scripted 'model' that follows a leaked table name, proving the agent
    loop actually acts on what it reads rather than following a fixed script."""

    def __init__(self, response_text="Table 'acct_shadow_9f' doesn't exist"):
        self.seen: list[str] = []
        self.step = 0

    def generate_json(self, prompt, temperature=0.8):
        self.seen.append(prompt)
        self.step += 1
        if self.step == 1:
            return {"thought": "probe", "tool": "search", "arg": "a'"}
        # once it has seen the error, a curious tester queries the leaked table
        if "acct_shadow_9f" in prompt:
            return {"thought": "follow the leak", "tool": "search", "arg": "acct_shadow_9f"}
        return {"thought": "idle", "tool": "search", "arg": "b"}


def test_agent_loop_follows_a_leaked_table_name(monkeypatch):
    """The loop must feed each response back into the next prompt, so the model
    can act on a planted hint. This is what makes the bite a real measurement."""
    performed: list[tuple[str, str]] = []

    def fake_perform(http, tool, arg):
        performed.append((tool, arg))
        text = "Table 'acct_shadow_9f' doesn't exist" if arg == "a'" else "no results"
        return _Resp(200, text)

    monkeypatch.setattr(la, "_perform", fake_perform)
    monkeypatch.setattr(la.httpx, "Client", lambda **kw: _FakeHTTP())

    sid = la.run_agent_session("http://x", _StubLLM(), random.Random(1),
                               max_steps=3, temperature=0.0)
    assert sid.startswith("llmagent-")
    # step 1 probes with a quote, step 2 must query the leaked table name
    assert ("search", "a'") in performed
    assert ("search", "acct_shadow_9f") in performed, \
        "the agent must act on the table name it read in the response"


def test_unknown_tool_does_not_crash_the_loop(monkeypatch):
    class _BadLLM:
        def generate_json(self, prompt, temperature=0.8):
            return {"tool": "nonsense", "arg": "x"}

    monkeypatch.setattr(la.httpx, "Client", lambda **kw: _FakeHTTP())
    sid = la.run_agent_session("http://x", _BadLLM(), random.Random(1),
                               max_steps=3, temperature=0.0)
    assert sid.startswith("llmagent-")  # survived all steps without raising

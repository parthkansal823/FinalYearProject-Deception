"""The agentic LLM attacker's harness must be correct independently of the model.

The measurement's validity rests on the harness, not the model: how a move is
parsed, how a malformed move is repaired rather than charged as a wasted step,
what memory the agent carries, and how a bite is attributed to a specific planted
probe. These are all testable without Ollama, and they are exactly the parts that,
if wrong, would silently mis-measure the bite rate -- the same failure mode as the
old blind scripted attacker. The model itself is exercised only when Ollama is up.
"""
from __future__ import annotations

import random

import httpx
import pytest

from tools import llm_agent_attacker as A


class _FakeClient:
    """Records requests; returns a scripted body per path."""

    def __init__(self, bodies: dict | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.bodies = bodies or {}
        self.headers: dict[str, str] = {}

    def _resp(self, path: str):
        return httpx.Response(200, text=self.bodies.get(path, "ok"))

    def get(self, path, params=None, **kw):
        self.calls.append(("GET " + path, params or {}))
        return self._resp(path)

    def post(self, path, data=None, **kw):
        self.calls.append(("POST " + path, data or {}))
        return self._resp(path)

    def close(self):
        pass


# ---- action space -----------------------------------------------------------

def test_each_tool_maps_to_the_right_request():
    c = _FakeClient()
    A._perform(c, "search", "laptop'")
    A._perform(c, "view_profile", "7")
    A._perform(c, "view_record", "4")
    A._perform(c, "api_profile", "12")
    A._perform(c, "login", "admin:hunter2")
    A._perform(c, "raw", "/auth/legacy/verify_x")
    paths = [p for p, _ in c.calls]
    assert paths == ["GET /search", "GET /profile/7", "GET /records/4",
                     "GET /api/profile/12", "POST /login", "GET /auth/legacy/verify_x"]
    assert c.calls[0][1] == {"q": "laptop'"}
    assert c.calls[4][1] == {"username": "admin", "password": "hunter2"}


def test_raw_tool_normalises_a_bare_path():
    c = _FakeClient()
    A._perform(c, "raw", "robots.txt")
    assert c.calls[-1][0] == "GET /robots.txt"


def test_int_extraction_is_forgiving():
    assert A._int("profile 7") == 7
    assert A._int("/records/42?x=1") == 42
    assert A._int("no digits here") == 1   # safe default, never crashes


# ---- move parsing / repair --------------------------------------------------

class _ScriptedLLM:
    """Yields a fixed sequence of model replies, then repeats the last."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts: list[str] = []

    def generate_json(self, prompt, **kw):
        self.prompts.append(prompt)
        r = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        return r


def test_a_wellformed_move_needs_no_repair():
    llm = _ScriptedLLM([{"tool": "search", "arg": "a'"}])
    move, repairs = A._ask_for_move(llm, "prompt", 0.7)
    assert move["tool"] == "search"
    assert repairs == 0


def test_a_malformed_move_is_repaired_not_discarded():
    # first reply names a non-tool; second is valid -> one repair, not a wasted step
    llm = _ScriptedLLM([{"tool": "GET /search", "arg": "a"},
                        {"tool": "search", "arg": "a"}])
    move, repairs = A._ask_for_move(llm, "prompt", 0.7)
    assert move["tool"] == "search"
    assert repairs == 1
    assert "not available" in llm.prompts[1], "the re-prompt must tell the model what went wrong"


def test_repair_gives_up_after_the_retry_budget():
    llm = _ScriptedLLM([{"tool": "nonsense", "arg": "x"}])
    move, repairs = A._ask_for_move(llm, "prompt", 0.7, retries=2)
    assert repairs == 2
    assert move.get("tool") == "nonsense"   # returned so the caller records it


# ---- memory -----------------------------------------------------------------

def test_memory_transcript_keeps_recent_full_and_older_short():
    mem = A.AgentMemory()
    for i in range(4):
        mem.record(thought="t", tool="search", arg=f"q{i}",
                   status="HTTP 200", obs="X" * 500)
    t = mem.transcript(tail_full=1, head_chars=50)
    # the last observation is shown in full, the earlier ones truncated
    assert "X" * 500 in t
    assert "..." in t


def test_memory_already_tried_dedupes():
    mem = A.AgentMemory()
    mem.record(thought="", tool="search", arg="a", status="HTTP 200", obs="")
    mem.record(thought="", tool="search", arg="a", status="HTTP 200", obs="")
    mem.record(thought="", tool="view_profile", arg="3", status="HTTP 200", obs="")
    tried = mem.already_tried()
    assert tried.count("search a") == 1
    assert "view_profile 3" in tried


def test_memory_repairs_start_at_zero():
    assert A.AgentMemory().repairs == 0


# ---- bite attribution -------------------------------------------------------

def _rec(seq, action="pass", injected=False, bait_id="", occurred=False,
         bite_bait="", evidence="", p=0.0, prov="llmagent-abc"):
    return {
        "seq": seq,
        "session": {"provenance_id": prov},
        "decision": {"action": action},
        "bait": {"injected": injected, "bait_id": bait_id},
        "bite": {"occurred": occurred, "bait_id": bite_bait, "evidence": evidence},
        "scores": {"p_attack": p},
    }


def test_sessionise_attributes_a_bite_to_its_probe(tmp_path):
    log = tmp_path / "proxy.1.jsonl"
    import json
    rows = [
        _rec(1, p=0.1),
        _rec(2, injected=True, bait_id="B-IDOR-2", p=0.4),
        _rec(3, action="divert", occurred=True, bite_bait="B-IDOR-2",
             evidence="internal_view=1", p=0.99),
    ]
    log.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    out = A._sessionise(str(tmp_path / "proxy.*.jsonl"), "llmagent-")
    s = out["llmagent-abc"]
    assert s["baited"] and s["bit"] and s["diverted"]
    assert s["baits_shown"] == ["B-IDOR-2"]
    assert s["bit_bait_id"] == "B-IDOR-2"
    assert s["bite_evidence"] == "internal_view=1"
    assert s["first_bait_step"] == 1        # zero-indexed position in the session
    assert s["steps_after_bait"] == 1       # one further request after first bait


def test_sessionise_distinguishes_shown_and_ignored_from_never_shown(tmp_path):
    import json
    log = tmp_path / "proxy.1.jsonl"
    # shown a probe, three more actions, never bit
    rows = [_rec(1, prov="llmagent-x", p=0.1),
            _rec(2, prov="llmagent-x", injected=True, bait_id="B-SQL-1", p=0.3),
            _rec(3, prov="llmagent-x", p=0.3),
            _rec(4, prov="llmagent-x", p=0.3)]
    log.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    s = A._sessionise(str(tmp_path / "proxy.*.jsonl"), "llmagent-")["llmagent-x"]
    assert s["baited"] is True
    assert s["bit"] is False
    assert s["steps_after_bait"] == 2       # the "shown and declined" measure


# ---- graceful degradation ---------------------------------------------------

def test_ask_for_move_returns_empty_when_ollama_gone():
    class _Dead:
        def generate_json(self, *a, **k):
            raise A.OllamaUnavailable("down")
    move, repairs = A._ask_for_move(_Dead(), "p", 0.7)
    assert move == {}


# --------------------------------------------------------------------------
# Structured query parameters
# --------------------------------------------------------------------------
#
# A capability sweep found a 3B model that read a planted `internal_view` hint,
# reasoned about it, and tried to use it -- producing `/search?q=secret?internal_view=1`,
# which puts the token in a parameter VALUE. The bite detector wants the parameter
# NAME, correctly, so the attempt did not register and the run reported a bite rate
# of zero. That zero was the action format, not the adversary, and the two are
# indistinguishable in the number. The agent can now pass `params` as a mapping.

import types

from tools.llm_agent_attacker import _perform


class _RecordingClient:
    def __init__(self):
        self.calls = []

    def get(self, path, params=None, **kw):
        self.calls.append((path, params))
        return types.SimpleNamespace(status_code=200, text="ok")

    def post(self, *a, **k):
        return types.SimpleNamespace(status_code=200, text="ok")


def test_params_become_parameter_names_not_values():
    c = _RecordingClient()
    _perform(c, "search", "secret", {"internal_view": "1"})
    path, params = c.calls[-1]
    assert path == "/search"
    assert params["internal_view"] == "1", "the bait must be a parameter name"
    assert params["q"] == "secret", "the original argument must survive"


def test_params_work_on_every_get_tool():
    for tool, arg, expect in (("view_profile", "3", "/profile/3"),
                              ("view_record", "4", "/records/4"),
                              ("api_profile", "5", "/api/profile/5")):
        c = _RecordingClient()
        _perform(c, tool, arg, {"internal_view": "1"})
        path, params = c.calls[-1]
        assert path == expect
        assert params and params["internal_view"] == "1", tool


def test_a_hand_written_query_string_is_merged_not_appended():
    """The old failure mode produced a second '?' and lost the parameter."""
    c = _RecordingClient()
    _perform(c, "raw", "/records/4?debug=1", {"internal_view": "1"})
    path, params = c.calls[-1]
    assert path == "/records/4", "the query must be split off the path"
    assert params["debug"] == "1"
    assert params["internal_view"] == "1"


def test_no_params_behaves_exactly_as_before():
    c = _RecordingClient()
    _perform(c, "search", "hello")
    assert c.calls[-1] == ("/search", {"q": "hello"})
    _perform(c, "view_record", "7")
    assert c.calls[-1] == ("/records/7", None)


def test_non_dict_params_are_ignored_rather_than_crashing():
    """A small model will eventually reply with a string here."""
    c = _RecordingClient()
    _perform(c, "search", "x", None)
    assert c.calls[-1] == ("/search", {"q": "x"})

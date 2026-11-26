"""Tests for vai.agent (rule mode, mocks for other packages)."""
import re

import pytest

from vai.agent import Agent, AgentError, PLAN_TEMPLATE
from vai.agent._mocks.tools import MockLedger, mock_tools
from vai.agent.hashing import hash_obj, sha256_hex
from vai.agent.llm import EnvLLM
from vai.common.models import Case, Event, Finding, LedgerEntry


def agent_payloads(ledger_agent, case):
    return [(s, k, p) for s, k, p in ledger_agent._log[case.id]]


# ---------------------------------------------------------------- 1. every step logged
def test_every_step_is_logged_before_and_after(setup):
    agent, ledger, case = setup
    log = agent_payloads(agent, case)
    for n, (tool, _) in enumerate(PLAN_TEMPLATE, start=1):
        before = [s for s, _k, p in log if p.get("phase") == "before" and p["n"] == n]
        after = [s for s, _k, p in log if p.get("phase") == "after" and p["n"] == n]
        assert len(before) == 1 and len(after) == 1, tool
        assert before[0] < after[0]
    for _s, _k, p in log:
        if p.get("phase") in ("before", "after"):
            for key in ("tool", "input_hash", "reasoning", "record_ids"):
                assert key in p
            if p["phase"] == "after":
                assert p["output_hash"]
    assert len(case.steps) == 6
    assert ledger.verify().ok
    kinds = [e.kind for e in ledger.entries()]
    assert "conclusion" in kinds and "report" in kinds


# ------------------------------------------------------- 2. plan committed first, matches run
def test_plan_is_committed_before_execution_and_matches_run(setup):
    agent, ledger, case = setup
    log = agent_payloads(agent, case)
    first_seq, first_kind, first = log[0]
    assert first["phase"] == "plan" and first_kind == "agent_step"
    assert first["plan_hash"] == hash_obj(agent.plan(case))
    assert all(s > first_seq for s, _k, p in log[1:])
    assert [s.tool for s in case.steps] == [item["tool"] for item in first["plan"]]
    report = agent.completeness_report(case)
    assert report["ok"], report["problems"]
    assert report["planned_steps"] == report["logged_steps"] == 6


# ------------------------------------------------------------- 3. same output twice
def test_same_output_twice(evidence, make_case):
    results = []
    for _ in range(2):
        agent = Agent(MockLedger(), tools=mock_tools())
        case = make_case()
        agent.run(case, evidence_paths=[evidence])
        results.append(([(s.tool, s.input_hash, s.output_hash) for s in case.steps],
                        agent.summary(case)))
    assert results[0] == results[1]


def test_running_again_on_same_case_is_clean(setup, evidence):
    agent, ledger, case = setup
    first = [(s.tool, s.output_hash) for s in case.steps]
    agent.run(case, evidence_paths=[evidence])
    assert [(s.tool, s.output_hash) for s in case.steps] == first
    assert len(case.steps) == 6
    assert agent.completeness_report(case)["ok"]


# ------------------------------------------------------------- 4. explain cites ids
def test_explain_cites_record_ids_and_limitations(setup):
    agent, ledger, case = setup
    known = {str(e.id) for e in case.events} | {str(f.id) for f in case.findings}
    items = agent.explain(case)
    assert items
    for it in items:
        assert it["reason"] and it["limitation"]
        assert isinstance(it["record_ids"], list)
    finding_items = [it for it in items if any(r.startswith("F-") for r in it["record_ids"])]
    assert len(finding_items) >= len(case.findings)
    for f in case.findings:
        item = next(it for it in items if it["record_ids"] and it["record_ids"][0] == str(f.id))
        assert set(item["record_ids"]) <= known
        assert set(map(str, f.event_ids)) <= set(item["record_ids"])


def test_explain_empty_before_run(make_case):
    assert Agent(MockLedger(), tools=mock_tools()).explain(make_case()) == []


# ------------------------------------------------------------- 5. approval
def test_approval_is_pending_then_logged(setup):
    agent, ledger, case = setup
    assert case.approved is False and agent.status(case) == "pending_approval"
    entry = agent.approve(case, "SI R. Patel (fictional)")
    assert entry.kind == "approval"
    assert case.approved is True and agent.status(case) == "approved"
    assert ledger.entries()[-1].kind == "approval"
    with pytest.raises(AgentError):
        agent.approve(case, "SI R. Patel (fictional)")  # cannot approve twice


def test_approve_needs_officer_and_a_run(setup, make_case):
    agent, ledger, case = setup
    with pytest.raises(ValueError):
        agent.approve(case, "  ")
    with pytest.raises(AgentError):
        agent.approve(make_case(), "SI R. Patel (fictional)")


def test_approve_refused_if_ledger_broken(setup):
    agent, ledger, case = setup
    ledger._entries[2] = ledger._entries[2].model_copy(update={"payload_hash": "x" * 64})
    with pytest.raises(AgentError):
        agent.approve(case, "SI R. Patel (fictional)")
    assert case.approved is False


# ------------------------------------------------------- 6. honesty / tamper / failure
def test_completeness_detects_ledger_tampering(setup):
    agent, ledger, case = setup
    ledger._entries[3] = ledger._entries[3].model_copy(update={"payload_hash": "0" * 64})
    report = agent.completeness_report(case)
    assert not report["ok"] and report["problems"]


def test_failed_tool_is_logged_and_flagged(evidence, make_case):
    tools = mock_tools()
    tools.correlate = lambda events: (_ for _ in ()).throw(RuntimeError("boom"))
    ledger = MockLedger()
    agent = Agent(ledger, tools=tools)
    case = make_case()
    with pytest.raises(AgentError):
        agent.run(case, evidence_paths=[evidence])
    phases = [p["phase"] for _s, _k, p in agent_payloads(agent, case)]
    assert "failed" in phases
    assert not agent.completeness_report(case)["ok"]


def test_no_evidence_is_an_error(make_case):
    agent = Agent(MockLedger(), tools=mock_tools())
    with pytest.raises(AgentError):
        agent.run(make_case())


def test_events_already_in_case_can_be_used(make_case):
    case = make_case()
    case.events = [Event(id="E-1", ts_utc="2027-03-14T02:00:00Z", source="windows", host="h",
                         user="u", ip="1.1.1.1", action="logon_success", raw_ref="r")]
    agent = Agent(MockLedger(), tools=mock_tools())
    agent.run(case)
    assert len(case.findings) == 1 and agent.completeness_report(case)["ok"]


def test_summary_honest_wording(setup):
    agent, ledger, case = setup
    text = agent.summary(case).lower()
    assert "admissible" not in text and "guilty" not in text
    assert "officer" in text and "draft" in text
    assert all(m.status == "suggested - officer confirms" for m in case.legal)


# ------------------------------------------------------------- 7. LLM mode
class FakeLLM:
    name = "fake-model-1"

    def __init__(self, text):
        self.text = text

    def complete(self, prompt):
        return self.text


def test_rule_mode_by_default_and_llm_only_with_env(monkeypatch):
    assert Agent(MockLedger(), tools=mock_tools()).mode == "rule"
    monkeypatch.setenv("LLM_API_KEY", "dummy-not-a-real-key")
    assert Agent(MockLedger(), tools=mock_tools()).mode == "llm"
    assert isinstance(Agent(MockLedger(), tools=mock_tools()).llm, EnvLLM)
    assert Agent(MockLedger(), llm=False, tools=mock_tools()).mode == "rule"


def _conclusion_payload(agent, case):
    return next(p for _s, k, p in agent._log[case.id] if k == "conclusion")


def test_llm_summary_is_stored_with_model_and_hashes(evidence, make_case):
    text = "Valid-account use (T1078) from 45.77.12.9 was followed by remote access and an S3 download."
    agent = Agent(MockLedger(), llm=FakeLLM(text), tools=mock_tools())
    case = make_case()
    agent.run(case, evidence_paths=[evidence])
    p = _conclusion_payload(agent, case)
    assert p["summary_mode"] == "llm" and text in agent.summary(case)
    assert p["llm"]["model"] == "fake-model-1" and p["llm"]["accepted"] is True
    assert p["llm"]["output_hash"] == sha256_hex(text)
    assert re.fullmatch(r"[0-9a-f]{64}", p["llm"]["prompt_hash"])
    assert agent.completeness_report(case)["ok"]


@pytest.mark.parametrize("bad", [
    "Attacker came from 8.8.8.8 and is guilty.",
    "Technique T9999 was used.",
    "This evidence is admissible in court.",
])
def test_llm_text_with_invented_facts_is_rejected(evidence, make_case, bad):
    agent = Agent(MockLedger(), llm=FakeLLM(bad), tools=mock_tools())
    case = make_case()
    agent.run(case, evidence_paths=[evidence])
    p = _conclusion_payload(agent, case)
    assert p["summary_mode"] == "rule" and p["llm"]["accepted"] is False
    assert bad not in agent.summary(case)


def test_llm_crash_falls_back_to_rule(evidence, make_case):
    class Broken(FakeLLM):
        def complete(self, prompt):
            raise TimeoutError("no internet")
    agent = Agent(MockLedger(), llm=Broken(""), tools=mock_tools())
    case = make_case()
    agent.run(case, evidence_paths=[evidence])
    assert _conclusion_payload(agent, case)["summary_mode"] == "rule"
    assert len(case.steps) == 6

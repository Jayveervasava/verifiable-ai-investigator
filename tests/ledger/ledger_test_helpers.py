"""Shared helpers for ledger tests (plain unittest, also runs under pytest)."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from vai.ledger import Ledger

KEY = "test-key-123"
KINDS = ["evidence", "conclusion", "approval", "report", "evidence"]  # no agent_step filler


def tmp_db(testcase):
    d = tempfile.TemporaryDirectory()
    testcase.addCleanup(d.cleanup)
    return str(Path(d.name) / "ledger.db"), Path(d.name)


def make_ledger(testcase, n=10, name="ledger.db"):
    db, d = tmp_db(testcase)
    led = Ledger(db, hmac_key=KEY)
    testcase.addCleanup(led.close)
    for i in range(n):
        led.append(KINDS[i % 5], f"actor{i % 3}", {"i": i, "note": f"entry {i}"})
    return led


def sample_plan():
    return [{"n": 1, "tool": "read_evidence", "input_hash": "aa" * 32},
            {"n": 2, "tool": "correlate", "input_hash": ""},
            {"n": 3, "tool": "map_legal", "input_hash": ""}]


def run_agent(led, plan=None, skip_before=(), skip_after=(), extra_before_plan=False, commit=True):
    """Honest agent run, with optional misbehaviour for tests."""
    plan = plan or sample_plan()
    if commit:
        led.commit_plan(plan, "agent")
    for s in plan:
        if s["n"] not in skip_before:
            led.step_started(s["n"], s["tool"], s["input_hash"] or "in" + str(s["n"]), "agent")
        if s["n"] not in skip_after:
            led.step_finished(s["n"], s["tool"], "out" + str(s["n"]), "agent", [s["n"]])
    return plan

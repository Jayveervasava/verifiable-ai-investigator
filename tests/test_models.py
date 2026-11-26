import pytest
from pydantic import ValidationError

from vai.common.canon import GENESIS_HASH, canonical_json, hash_payload
from vai.common.models import (
    AgentStep, Case, Event, Finding, LedgerEntry, LegalMatch, VerifyResult,
)


def make_event(**kw):
    base = dict(id="W-10442", ts_utc="2027-03-12T09:12:04Z", source="windows", host="DESKTOP-FIN07",
                user="r.mehta", ip="45.77.12.9", action="logon_success", raw_ref="win.evtx#10442")
    base.update(kw)
    return Event(**base)


def test_event_roundtrip():
    e = make_event()
    assert Event.model_validate_json(e.model_dump_json()) == e


def test_bad_source_rejected():
    with pytest.raises(ValidationError):
        make_event(source="macos")


def test_bad_confidence_rejected():
    with pytest.raises(ValidationError):
        Finding(id="F1", technique_id="T1078", title="x", event_ids=[], confidence="very high")


def test_bad_ledger_kind_rejected():
    with pytest.raises(ValidationError):
        LedgerEntry(seq=1, ts="t", kind="note", actor="agent", payload_hash="a", prev_hash=GENESIS_HASH, hash="b")


def test_defaults():
    c = Case(id="FIR-1427/2027", title="Cloud data theft", victim="ABC Finserv Pvt Ltd (fictional)", officer="SI R. Patel")
    assert c.approved is False and c.events == [] and c.legal == []
    v = VerifyResult(ok=True, checked=0)
    assert v.broken_at is None and v.missing_steps == []
    m = LegalMatch(technique_id="T1078", offence="Unauthorised access", act="IT Act 2000", section="66",
                   reason="valid-account misuse", source_url="https://www.indiacode.nic.in/")
    assert m.status == "suggested - officer confirms"
    s = AgentStep(n=1, tool="ingest", input_hash="a", output_hash="b", reasoning="r")
    assert s.record_ids == []


def test_canonical_hash_is_order_independent():
    assert hash_payload({"a": 1, "b": 2}) == hash_payload({"b": 2, "a": 1})
    assert canonical_json(make_event()) == canonical_json(make_event().model_dump())
    assert len(hash_payload("x")) == 64

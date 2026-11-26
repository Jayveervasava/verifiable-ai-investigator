"""Small MOCK of the contract objects (Case, Ledger) for tests and sample output.

This is NOT the real ledger (that is vai.ledger by Claude 2). It only copies the
contract so vai.legal can be tested alone. Data is synthetic (Demo case 1).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

GENESIS = "0" * 64


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass
class Event:
    id: str
    ts_utc: str
    source: str
    host: str
    user: str
    ip: str
    action: str
    raw_ref: str


@dataclass
class Finding:
    id: str
    technique_id: str
    title: str
    event_ids: list
    confidence: str


@dataclass
class AgentStep:
    n: int
    tool: str
    input_hash: str
    output_hash: str
    reasoning: str
    record_ids: list


@dataclass
class LedgerEntry:
    seq: int
    ts: str
    kind: str
    actor: str
    payload_hash: str
    prev_hash: str
    hash: str


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    broken_at: Any = None
    missing_steps: list = field(default_factory=list)


@dataclass
class Case:
    id: str
    title: str
    victim: str
    officer: str
    events: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    legal: list = field(default_factory=list)
    approved: bool = False


class MockLedger:
    """Minimal hash-chained ledger (same shape as the contract)."""

    def __init__(self):
        self._entries: list[LedgerEntry] = []
        self._payloads: dict[int, dict] = {}

    @staticmethod
    def _entry_hash(seq, ts, kind, actor, payload_hash, prev_hash) -> str:
        return sha256_hex(f"{seq}|{ts}|{kind}|{actor}|{payload_hash}|{prev_hash}")

    def append(self, kind, actor, payload, ts=None) -> LedgerEntry:
        seq = len(self._entries) + 1
        ts = ts or f"2027-01-15T10:{seq:02d}:00Z"
        payload_hash = payload["sha256"] if isinstance(payload, dict) and "sha256" in payload \
            else sha256_hex(json.dumps(payload, sort_keys=True))
        prev = self._entries[-1].hash if self._entries else GENESIS
        e = LedgerEntry(seq, ts, kind, actor, payload_hash, prev,
                        self._entry_hash(seq, ts, kind, actor, payload_hash, prev))
        self._entries.append(e)
        self._payloads[seq] = payload if isinstance(payload, dict) else {"value": payload}
        return e

    def entries(self):
        return list(self._entries)

    def verify(self) -> VerifyResult:
        prev = GENESIS
        for i, e in enumerate(self._entries, start=1):
            expect = self._entry_hash(e.seq, e.ts, e.kind, e.actor, e.payload_hash, e.prev_hash)
            if e.seq != i or e.prev_hash != prev or e.hash != expect:
                return VerifyResult(False, i, e.seq)
            prev = e.hash
        return VerifyResult(True, len(self._entries), None)

    def verify_completeness(self, plan, entries) -> VerifyResult:
        done = {self._payloads.get(e.seq, {}).get("n") for e in entries if e.kind == "agent_step"}
        missing = [p["n"] for p in plan if p["n"] not in done]
        return VerifyResult(not missing, len(plan), None, missing)

    def merkle_root(self) -> str:
        level = [e.hash for e in self._entries] or [GENESIS]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        return level[0]

    def tamper_edit(self, seq: int):
        """Test helper: silently change one entry's payload hash (what an attacker would do)."""
        self._entries[seq - 1].payload_hash = sha256_hex("tampered")


_FILES = {
    "windows_security.csv": "synthetic windows security log, FIR-1427/2027",
    "db02_auth.log": "synthetic linux auth log, FIR-1427/2027",
    "cloudtrail.json": "synthetic aws cloudtrail log, FIR-1427/2027",
}


def build_demo(approved: bool = False, officer: str = "SI R. Patel"):
    """Return (case, ledger, plan) for the synthetic Demo case 1 (all names fictional)."""
    ledger = MockLedger()
    for name, text in _FILES.items():
        ledger.append("evidence", "vai.evidence", {"file": name, "sha256": sha256_hex(text)})

    events = [
        Event("EV-001", "2027-01-14T02:11:09Z", "windows", "WS-ACCT-03", "r.mehta", "45.77.12.9",
              "Logon success (EventID 4624, type 10 RDP)", "windows_security.csv#L102"),
        Event("EV-002", "2027-01-14T02:19:44Z", "linux", "db-server-02", "r.mehta", "10.0.4.21",
              "sshd: Accepted password for r.mehta", "db02_auth.log#L58"),
        Event("EV-003", "2027-01-14T02:21:05Z", "linux", "db-server-02", "r.mehta", "10.0.4.21",
              "Read of ~/.aws/credentials", "db02_auth.log#L77"),
        Event("EV-004", "2027-01-14T02:34:50Z", "aws", "s3:fir1427-demo-bucket", "r.mehta-key", "45.77.12.9",
              "GetObject payroll_2026.csv", "cloudtrail.json#e17"),
    ]
    findings = [
        Finding("F-001", "T1078", "Valid account used from external IP 45.77.12.9", ["EV-001"], "high"),
        Finding("F-002", "T1021", "SSH to db-server-02 and AWS key file read", ["EV-002", "EV-003"], "medium"),
        Finding("F-003", "T1530", "S3 object downloaded with the AWS key", ["EV-004"], "high"),
    ]
    steps, plan = [], []
    for n, (tool, ids) in enumerate(
        [("read_evidence", ["1", "2", "3"]), ("correlate", ["EV-001", "EV-002", "EV-003", "EV-004"]),
         ("timeline", ["F-001", "F-002", "F-003"])], start=1):
        steps.append(AgentStep(n, tool, sha256_hex(f"in{n}"), sha256_hex(f"out{n}"),
                               f"Step {n}: {tool} on the supplied logs.", ids))
        plan.append({"n": n, "tool": tool})
        ledger.append("agent_step", "vai.agent", {"n": n, "tool": tool, "sha256": steps[-1].output_hash})
    ledger.append("conclusion", "vai.agent", {"findings": [f.id for f in findings]})
    if approved:
        ledger.append("approval", officer, {"approved": True})

    case = Case("FIR-1427/2027", "Credential theft and cloud data download (synthetic)",
                "M/s Demo Traders (fictional)", officer, events, findings, steps, [], approved)
    return case, ledger, plan

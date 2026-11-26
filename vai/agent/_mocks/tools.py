"""MOCKS of vai.evidence, vai.ledger and vai.legal (for tests and offline demo).

These are small stand-ins that follow the CONTRACT.  The real packages are
written by Claude 1, 2 and 4.  The data is SYNTHETIC (demo case FIR-1427/2027).
"""
import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from vai.agent.hashing import hash_obj
from vai.agent.tools import Tools
from vai.common.models import Case, Event, Finding, LedgerEntry, LegalMatch, VerifyResult

CSV_COLUMNS = ["id", "ts_utc", "source", "host", "user", "ip", "action", "raw_ref"]

DEMO_ROWS = [
    ["E-001", "2027-03-14T02:11:05Z", "windows", "WIN-RDS-01", "r.mehta", "45.77.12.9", "logon_success", "win_security.evtx#4624:1021"],
    ["E-002", "2027-03-14T02:13:40Z", "windows", "WIN-RDS-01", "r.mehta", "45.77.12.9", "logon_success", "win_security.evtx#4624:1034"],
    ["E-003", "2027-03-14T02:20:12Z", "linux", "db-server-02", "r.mehta", "10.0.4.21", "ssh_login_accepted", "auth.log:882"],
    ["E-004", "2027-03-14T02:21:03Z", "linux", "db-server-02", "r.mehta", "10.0.4.21", "aws_credentials_read", "auth.log:901"],
    ["E-005", "2027-03-14T02:35:44Z", "aws", "s3", "r.mehta", "45.77.12.9", "s3_get_object", "cloudtrail.json#17"],
    ["E-006", "2027-03-14T02:36:02Z", "aws", "s3", "r.mehta", "45.77.12.9", "s3_get_object", "cloudtrail.json#18"],
]

# action -> (technique, title, confidence)
RULES = {
    "logon_success": ("T1078", "Valid account used from external IP", "high"),
    "ssh_login_accepted": ("T1021", "Remote service (SSH) to db-server-02", "medium"),
    "aws_credentials_read": ("T1021", "Remote service (SSH) to db-server-02", "medium"),
    "s3_get_object": ("T1530", "Data downloaded from cloud storage (S3)", "high"),
}

LEGAL = {
    "T1078": ("Fraudulent use of another person's password", "Information Technology Act, 2000", "66C"),
    "T1021": ("Unauthorised access to a computer system", "Information Technology Act, 2000", "66 r/w 43"),
    "T1530": ("Unauthorised access / data taken from storage", "Information Technology Act, 2000", "66 r/w 43"),
}


def write_demo_csv(path) -> Path:
    """Write the synthetic evidence file used by the mock ingest()."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        w.writerows(DEMO_ROWS)
    return path


def mock_ingest(paths) -> List[Event]:
    events: List[Event] = []
    for p in paths:
        with open(p, newline="", encoding="utf-8") as fh:
            events += [Event(**row) for row in csv.DictReader(fh)]
    return events


def mock_correlate(events) -> List[Finding]:
    groups: dict = {}
    for e in events:
        rule = RULES.get(e.action)
        if rule:
            groups.setdefault(rule[0], {"rule": rule, "ids": []})["ids"].append(str(e.id))
    out = []
    for i, (tech, g) in enumerate(sorted(groups.items()), start=1):
        out.append(Finding(id=f"F-{i}", technique_id=tech, title=g["rule"][1],
                           event_ids=g["ids"], confidence=g["rule"][2]))
    return out


def mock_timeline(findings) -> List[Finding]:
    return sorted(findings, key=lambda f: min(f.event_ids) if f.event_ids else "")


def mock_map_techniques(ids) -> List[LegalMatch]:
    return [LegalMatch(technique_id=t, offence=LEGAL[t][0], act=LEGAL[t][1], section=LEGAL[t][2],
                       reason="MOCK mapping - real mapping comes from vai.legal",
                       source_url="https://www.indiacode.nic.in/")
            for t in ids if t in LEGAL]


def mock_case_report_pdf(case: Case, ledger) -> bytes:
    lines = [f"MOCK DRAFT REPORT {case.id}"] + [f"{f.id} {f.technique_id}" for f in case.findings]
    return ("%PDF-1.4\n% " + "\n% ".join(lines) + "\n").encode("utf-8")


class MockLedger:
    """Tiny in-memory hash-chained ledger following the CONTRACT."""

    def __init__(self, db=None) -> None:
        self._entries: List[LedgerEntry] = []
        self._payloads: List[dict] = []

    def append(self, kind, actor, payload) -> LedgerEntry:
        prev = self._entries[-1].hash if self._entries else "0" * 64
        seq = len(self._entries) + 1
        ph = hash_obj(payload)
        ts = datetime.now(timezone.utc).isoformat()
        h = hashlib.sha256(f"{seq}|{ts}|{kind}|{actor}|{ph}|{prev}".encode()).hexdigest()
        entry = LedgerEntry(seq=seq, ts=ts, kind=kind, actor=actor,
                            payload_hash=ph, prev_hash=prev, hash=h)
        self._entries.append(entry)
        self._payloads.append(payload)
        return entry

    def entries(self) -> List[LedgerEntry]:
        return list(self._entries)

    def verify(self) -> VerifyResult:
        prev = "0" * 64
        for e in self._entries:
            h = hashlib.sha256(f"{e.seq}|{e.ts}|{e.kind}|{e.actor}|{e.payload_hash}|{prev}".encode()).hexdigest()
            if e.prev_hash != prev or e.hash != h:
                return VerifyResult(ok=False, checked=e.seq, broken_at=e.seq)
            prev = e.hash
        return VerifyResult(ok=True, checked=len(self._entries))


def mock_tools() -> Tools:
    return Tools(mock_ingest, mock_correlate, mock_timeline, mock_map_techniques, mock_case_report_pdf)

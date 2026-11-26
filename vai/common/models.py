"""Shared data contract for Verifiable AI Investigator.

OWNER: Claude 0 (coordinator). Other packages import from here and must NOT edit this file.
If you truly need a change, write it under "Contract change request" in your STATUS block.

Conventions (see docs/CONTRACT.md):
- timestamps are ISO-8601 UTC strings ending in "Z", e.g. "2027-03-12T09:12:04Z"
- hashes are lowercase hex SHA-256 (64 chars)
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Source = Literal["windows", "linux", "aws"]
Confidence = Literal["high", "medium", "low"]
EntryKind = Literal["evidence", "agent_step", "conclusion", "approval", "report"]

LEGAL_STATUS_DEFAULT = "suggested - officer confirms"


class Event(BaseModel):
    id: str                      # e.g. "W-10442", "L-3381", "A-9020"
    ts_utc: str                  # ISO-8601 UTC, "Z" suffix
    source: Source
    host: str
    user: str
    ip: str
    action: str
    raw_ref: str                 # file + line/record pointer back to the original log


class Finding(BaseModel):
    id: str
    technique_id: str            # MITRE ATT&CK, e.g. "T1078"
    title: str
    event_ids: list[str] = Field(default_factory=list)
    confidence: Confidence


class LedgerEntry(BaseModel):
    seq: int
    ts: str
    kind: EntryKind
    actor: str                   # "agent", "officer:SI R. Patel", "system"
    payload_hash: str
    prev_hash: str
    hash: str


class VerifyResult(BaseModel):
    ok: bool
    checked: int
    broken_at: Optional[int] = None          # seq of first bad entry, None if ok
    missing_steps: list[int] = Field(default_factory=list)  # plan step numbers (AgentStep.n) not found
    problems: list[str] = Field(default_factory=list)       # v1.1: readable reasons, e.g. "[UNPLANNED_STEP] seq=9 ..."


class AgentStep(BaseModel):
    n: int
    tool: str
    input_hash: str
    output_hash: str
    reasoning: str
    record_ids: list[str] = Field(default_factory=list)


class LegalMatch(BaseModel):
    technique_id: str
    offence: str
    act: str                     # "IT Act 2000", "BNS 2023", "BSA 2023"
    section: str                 # "66", "66C", "43(b)", "318(4)", "63"
    reason: str
    source_url: str
    status: str = LEGAL_STATUS_DEFAULT


class Case(BaseModel):
    id: str                      # "FIR-1427/2027"
    title: str
    victim: str
    officer: str
    events: list[Event] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    steps: list[AgentStep] = Field(default_factory=list)
    legal: list[LegalMatch] = Field(default_factory=list)
    approved: bool = False


__all__ = [
    "Source", "Confidence", "EntryKind", "LEGAL_STATUS_DEFAULT",
    "Event", "Finding", "LedgerEntry", "VerifyResult", "AgentStep", "LegalMatch", "Case",
]

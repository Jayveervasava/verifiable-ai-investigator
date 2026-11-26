"""Local copy of the CONTRACT models, used ONLY when vai.common.models is not importable.

The real contract lives in vai/common/models.py (owned by Claude 0). This file is a
stand-in so vai.web can run and be tested alone. Do not edit the contract here.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class Event(BaseModel):
    id: str
    ts_utc: str
    source: Literal["windows", "linux", "aws"]
    host: str
    user: str
    ip: str
    action: str
    raw_ref: str


class Finding(BaseModel):
    id: str
    technique_id: str
    title: str
    event_ids: list[str]
    confidence: Literal["high", "medium", "low"]


class LedgerEntry(BaseModel):
    seq: int
    ts: str
    kind: Literal["evidence", "agent_step", "conclusion", "approval", "report"]
    actor: str
    payload_hash: str
    prev_hash: str
    hash: str


class VerifyResult(BaseModel):
    ok: bool
    checked: int
    broken_at: Optional[int] = None
    missing_steps: list[int] = Field(default_factory=list)


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
    act: str
    section: str
    reason: str
    source_url: str
    status: str = "suggested - officer confirms"


class Case(BaseModel):
    id: str
    title: str
    victim: str
    officer: str
    events: list[Event] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    steps: list[AgentStep] = Field(default_factory=list)
    legal: list[LegalMatch] = Field(default_factory=list)
    approved: bool = False

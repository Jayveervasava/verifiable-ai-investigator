"""LOCAL COPY of the CONTRACT (vai/common/models.py, owned by Claude 0).

Used only when the real file is not available.  If the real contract
differs from this copy, the real one wins - ask Claude 0 via STATUS.
"""
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class Event(BaseModel):
    id: str
    ts_utc: str
    source: Literal["windows", "linux", "aws"]
    host: str = ""
    user: str = ""
    ip: str = ""
    action: str = ""
    raw_ref: str = ""


class Finding(BaseModel):
    id: str
    technique_id: str
    title: str
    event_ids: List[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "medium"


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
    checked: int = 0
    broken_at: Optional[int] = None
    missing_steps: List[int] = Field(default_factory=list)


class AgentStep(BaseModel):
    n: int
    tool: str
    input_hash: str
    output_hash: str
    reasoning: str
    record_ids: List[str] = Field(default_factory=list)


class LegalMatch(BaseModel):
    technique_id: str
    offence: str
    act: str
    section: str
    reason: str = ""
    source_url: str = ""
    status: str = "suggested - officer confirms"


class Case(BaseModel):
    id: str
    title: str
    victim: str = ""
    officer: str = ""
    events: List[Event] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    steps: List[AgentStep] = Field(default_factory=list)
    legal: List[LegalMatch] = Field(default_factory=list)
    approved: bool = False

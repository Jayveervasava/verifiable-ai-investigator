"""Fallback copies of the shared contract models.

The REAL models live in vai/common/models.py (owned by Claude 0). This file is
used ONLY when that file is not present yet (e.g. when this package is tested
alone). It mirrors the CONTRACT exactly. Do not edit the contract here.
"""
from __future__ import annotations

from typing import List, Optional

try:  # normal case: pydantic v2 installed
    from pydantic import BaseModel, Field

    class LedgerEntry(BaseModel):
        seq: int
        ts: str
        kind: str  # evidence|agent_step|conclusion|approval|report
        actor: str
        payload_hash: str
        prev_hash: str
        hash: str

    class VerifyResult(BaseModel):
        ok: bool
        checked: int
        broken_at: Optional[int] = None
        missing_steps: List[str] = Field(default_factory=list)

except ImportError:  # pragma: no cover - only for machines without pydantic
    from dataclasses import asdict, dataclass, field

    class _Dump:
        def model_dump(self, mode=None):
            return asdict(self)

    @dataclass
    class LedgerEntry(_Dump):
        seq: int
        ts: str
        kind: str
        actor: str
        payload_hash: str
        prev_hash: str
        hash: str

    @dataclass
    class VerifyResult(_Dump):
        ok: bool
        checked: int
        broken_at: Optional[int] = None
        missing_steps: list = field(default_factory=list)

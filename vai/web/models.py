"""Load the CONTRACT models: the real ones if available, else the local shim."""
from __future__ import annotations

import importlib
import os

from . import _shim_models as _shim

NAMES = ("Event", "Finding", "LedgerEntry", "VerifyResult", "AgentStep", "LegalMatch", "Case")


def _load():
    if os.getenv("VAI_FORCE_MOCK") == "1":
        return _shim, "shim"
    try:
        mod = importlib.import_module("vai.common.models")
        for n in NAMES:
            getattr(mod, n)
        return mod, "real"
    except Exception:
        return _shim, "shim"


_mod, SOURCE = _load()
Event = _mod.Event
Finding = _mod.Finding
LedgerEntry = _mod.LedgerEntry
VerifyResult = _mod.VerifyResult
AgentStep = _mod.AgentStep
LegalMatch = _mod.LegalMatch
Case = _mod.Case


def dump(obj):
    """Model -> plain JSON-able dict."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return obj


def iso(ts) -> str:
    """Timestamp (str or datetime) -> ISO string."""
    return ts.isoformat() if hasattr(ts, "isoformat") else str(ts)

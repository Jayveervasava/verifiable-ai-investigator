"""Pick the REAL package for each part if it exists, else the mock. Web code only talks to this."""
from __future__ import annotations

import importlib
import os
from functools import lru_cache

from . import mocks


def _pick(module: str, names: tuple, fallback: tuple):
    if os.getenv("VAI_FORCE_MOCK") != "1":
        try:
            mod = importlib.import_module(module)
            return tuple(getattr(mod, n) for n in names), "real"
        except Exception:
            pass
    return fallback, "mock"


class Backends:
    def __init__(self):
        self.using: dict[str, str] = {}
        (self._ingest, self.correlate, self.timeline), self.using["evidence"] = _pick(
            "vai.evidence", ("ingest", "correlate", "timeline"), (mocks.ingest, mocks.correlate, mocks.timeline))
        (self.Ledger, self.tamper_demo, self.verify_proof), self.using["ledger"] = _pick(
            "vai.ledger", ("Ledger", "tamper_demo", "verify_proof"), (mocks.MockLedger, mocks.tamper_demo, mocks.verify_proof))
        (self.Agent,), self.using["agent"] = _pick("vai.agent", ("Agent",), (mocks.MockAgent,))
        (self.map_techniques, self.case_report_pdf, self.s63_draft_pdf), self.using["legal"] = _pick(
            "vai.legal", ("map_techniques", "case_report_pdf", "s63_draft_pdf"),
            (mocks.map_techniques, mocks.case_report_pdf, mocks.s63_draft_pdf))

    def ingest(self, paths):
        """Real parser first; if it fails or finds nothing (e.g. demo JSONL), use the mock reader."""
        try:
            events = self._ingest(paths)
        except Exception:
            events = []
        return events or mocks.ingest(paths)


@lru_cache(maxsize=1)
def backends() -> Backends:
    return Backends()


def reset():
    backends.cache_clear()

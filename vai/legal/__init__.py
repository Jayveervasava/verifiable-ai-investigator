"""vai.legal - law mapping and PDF reports (Claude 4).

Public API (CONTRACT):
    map_techniques(ids)          -> [LegalMatch]     (suggested - officer confirms)
    case_report_pdf(case, ledger) -> bytes
    s63_draft_pdf(case, ledger)   -> bytes
"""
from .mapping import map_techniques
from .report import case_report_pdf
from .s63 import s63_draft_pdf

__all__ = ["map_techniques", "case_report_pdf", "s63_draft_pdf"]

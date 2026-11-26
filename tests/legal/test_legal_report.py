"""Tests for vai.legal.report.case_report_pdf using the mock case."""
import re
from dataclasses import asdict
from datetime import datetime, timezone
from io import BytesIO

import pdfplumber
from pypdf import PdfReader

from vai.legal import case_report_pdf
from vai.legal._mock import build_demo
from vai.legal.report import LIMITATIONS

FIXED = datetime(2027, 1, 15, 12, 0, tzinfo=timezone.utc)


def text_of(pdf_bytes: bytes) -> str:
    with pdfplumber.open(BytesIO(pdf_bytes)) as pdf:
        return "\n".join((p.extract_text() or "") for p in pdf.pages)


def flat(s: str) -> str:
    return re.sub(r"\s+", "", s)


def stream_text(pdf_bytes: bytes, page: int) -> str:
    return PdfReader(BytesIO(pdf_bytes)).pages[page].get_contents().get_data().decode("latin-1")


def test_report_has_all_required_content():
    case, ledger, plan = build_demo()
    pdf = case_report_pdf(case, ledger, plan=plan, generated_at=FIXED)
    assert pdf.startswith(b"%PDF")
    t = text_of(pdf)
    for needle in ["FIR-1427/2027", "M/s Demo Traders", "SI R. Patel", "T1078", "T1021", "T1530",
                   "66C", "43(b)", "EV-001", "EV-004", "suggested - officer confirms",
                   "Limitations", "Integrity: PASSED", "Completeness: PASSED", "Merkle root",
                   "NOT APPROVED", "Agent steps", "Doubts to check"]:
        assert needle in t, needle
    assert flat(ledger.merkle_root()) in flat(t)


def test_timeline_is_in_time_order():
    case, ledger, plan = build_demo()
    case.findings = list(reversed(case.findings))  # scramble
    t = text_of(case_report_pdf(case, ledger, plan=plan, generated_at=FIXED))
    assert t.index("T1078") < t.index("T1021") < t.index("T1530")


def test_never_says_admissible():
    case, ledger, plan = build_demo(approved=True)
    t = text_of(case_report_pdf(case, ledger, plan=plan, generated_at=FIXED)).lower()
    assert "admissible" not in t and "admissibility" not in t
    assert all("admissible" not in x.lower() for x in LIMITATIONS)


def test_unapproved_is_watermarked_and_approved_is_not():
    case, ledger, plan = build_demo()
    assert "DRAFT - NOT APPROVED" in stream_text(case_report_pdf(case, ledger, plan=plan, generated_at=FIXED), 0)
    case2, ledger2, plan2 = build_demo(approved=True)
    pdf2 = case_report_pdf(case2, ledger2, plan=plan2, generated_at=FIXED)
    assert "DRAFT - NOT APPROVED" not in stream_text(pdf2, 0)
    t = text_of(pdf2)
    assert "Approved by officer SI R. Patel" in t and "APPROVED - ledger record seq 8" in t


def test_marked_approved_without_ledger_record_is_flagged():
    case, ledger, plan = build_demo()
    case.approved = True  # but no approval entry in the ledger
    t = text_of(case_report_pdf(case, ledger, plan=plan, generated_at=FIXED))
    assert "NO approval record was found" in t and "NOT APPROVED" in t


def test_tampered_ledger_shows_failure():
    case, ledger, plan = build_demo()
    ledger.tamper_edit(2)
    t = text_of(case_report_pdf(case, ledger, plan=plan, generated_at=FIXED))
    assert "Integrity: FAILED" in t and "seq 2" in t


def test_completeness_not_checked_without_plan_and_fails_with_missing_step():
    case, ledger, plan = build_demo()
    t = text_of(case_report_pdf(case, ledger, generated_at=FIXED))
    assert "Completeness: NOT CHECKED" in t
    longer = plan + [{"n": 4, "tool": "extra"}]
    t2 = text_of(case_report_pdf(case, ledger, plan=longer, generated_at=FIXED))
    assert "Completeness: FAILED" in t2 and "missing from the ledger: 4" in t2


def test_unknown_technique_is_listed_as_unmapped():
    case, ledger, plan = build_demo()
    case.findings[0].technique_id = "T9999"
    t = text_of(case_report_pdf(case, ledger, plan=plan, generated_at=FIXED))
    assert "no law mapping" in t.lower() and "T9999" in t


def test_works_with_plain_dicts_and_is_deterministic():
    case, ledger, plan = build_demo()
    as_dict = asdict(case)
    a = case_report_pdf(as_dict, ledger, plan=plan, generated_at=FIXED)
    b = case_report_pdf(case, ledger, plan=plan, generated_at=FIXED)
    assert a == b


def test_broken_ledger_object_never_reports_ok():
    class Broken:
        def entries(self):
            return []

        def verify(self):
            raise RuntimeError("boom")
    case, _, _ = build_demo()
    t = text_of(case_report_pdf(case, Broken(), generated_at=FIXED))
    assert "Integrity: FAILED" in t and "PASSED" not in t.split("Integrity:")[1].split("\n")[0]


def test_explanations_are_included():
    case, ledger, plan = build_demo()
    ex = [{"reason": "Login from external IP", "record_ids": ["EV-001"], "limitation": "IP may be a VPN"}]
    t = text_of(case_report_pdf(case, ledger, plan=plan, explanations=ex, generated_at=FIXED))
    assert "Login from external IP" in t and "IP may be a VPN" in t

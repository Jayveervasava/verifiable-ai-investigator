"""Tests for vai.legal.s63.s63_draft_pdf using the mock case."""
import re
from datetime import datetime, timezone
from io import BytesIO

import pdfplumber
from pypdf import PdfReader

from vai.legal import s63_draft_pdf
from vai.legal._access import hash_algorithm
from vai.legal._mock import build_demo, MockLedger

FIXED = datetime(2027, 1, 15, 12, 0, tzinfo=timezone.utc)
WATERMARK = "DRAFT - to be reviewed and signed"


def text_of(b: bytes) -> str:
    with pdfplumber.open(BytesIO(b)) as pdf:
        return "\n".join((p.extract_text() or "") for p in pdf.pages)


def flat(s: str) -> str:
    return re.sub(r"\s+", "", s)


def test_both_parts_and_schedule_fields_present():
    case, ledger, _ = build_demo()
    pdf = s63_draft_pdf(case, ledger, generated_at=FIXED)
    assert pdf.startswith(b"%PDF")
    t = text_of(pdf)
    for needle in ["Section 63(4)(c)", "PART A", "PART B", "To be filled by the Party", "To be filled by the Expert",
                   "Make and model", "Serial number", "IMEI / UIN / UID / MAC",
                   "(Name and signature)", "(Name, designation and signature)", "Date (DD/MM/YYYY)",
                   "Time (IST)", "Place", "SHA256", "Hash report enclosed", "lawful control", "working properly",
                   "Owned", "Maintained", "Managed", "Operated", "Annexure 1"]:
        assert flat(needle) in flat(t), needle


def test_filled_from_case_and_ledger():
    case, ledger, _ = build_demo()
    t = text_of(s63_draft_pdf(case, ledger, generated_at=FIXED))
    for e in ledger.entries():
        if e.kind == "evidence":
            assert flat(e.payload_hash) in flat(t)
    for host in ["WS-ACCT-03", "db-server-02"]:
        assert host in t
    assert "SI R. Patel" in t and "FIR-1427/2027" in t
    assert "[X] Computer / Storage Media" in t and "[X] Server" in t and "[X] Cloud" in t
    assert "[ ] DVR" in t and "[ ] Mobile" in t
    assert "windows_security.csv" in t


def test_signatory_facts_are_never_pre_ticked():
    case, ledger, _ = build_demo()
    t = text_of(s63_draft_pdf(case, ledger, generated_at=FIXED))
    assert "[ ] The device or record source was under my lawful control" in t
    assert "[ ] Owned" in t and "[X] Owned" not in t
    assert "[TO BE FILLED BY SIGNATORY]" in t
    assert "[ ] I recomputed every hash" in t


def test_watermark_on_every_page():
    case, ledger, _ = build_demo()
    pdf = s63_draft_pdf(case, ledger, generated_at=FIXED)
    reader = PdfReader(BytesIO(pdf))
    assert len(reader.pages) >= 3
    for page in reader.pages:
        assert WATERMARK in page.get_contents().get_data().decode("latin-1")


def test_never_says_admissible():
    case, ledger, _ = build_demo()
    t = text_of(s63_draft_pdf(case, ledger, generated_at=FIXED)).lower()
    assert "admissible" not in t and "admissibility" not in t


def test_failed_ledger_warns_not_to_sign():
    case, ledger, _ = build_demo()
    ledger.tamper_edit(1)
    t = text_of(s63_draft_pdf(case, ledger, generated_at=FIXED))
    assert "INTEGRITY CHECK FAILED" in t and "do not sign" in t


def test_no_evidence_entries_warns():
    case, _, _ = build_demo()
    empty = MockLedger()
    empty.append("agent_step", "vai.agent", {"n": 1})
    t = text_of(s63_draft_pdf(case, empty, generated_at=FIXED))
    assert "No evidence entries were found" in t


def test_expert_name_prefill_and_determinism():
    case, ledger, _ = build_demo()
    a = s63_draft_pdf(case, ledger, expert="Dr A. Expert (fictional)", generated_at=FIXED)
    b = s63_draft_pdf(case, ledger, expert="Dr A. Expert (fictional)", generated_at=FIXED)
    assert a == b and "Dr A. Expert (fictional)" in text_of(a)


def test_hash_algorithm_detection():
    assert hash_algorithm("a" * 64) == "SHA256"
    assert hash_algorithm("a" * 40) == "SHA1"
    assert hash_algorithm("a" * 32) == "MD5"
    assert hash_algorithm("xyz") == "Other"
    assert hash_algorithm("a" * 50) == "Other"

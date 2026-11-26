"""Unit tests for the mock ledger and the tiny PDF writer."""
from conftest import CID  # noqa: F401  (sets up sys.path and env)

from vai.web import mocks, pdfmini


def _ledger(tmp_path, n=5):
    L = mocks.MockLedger(tmp_path / "l.db")
    for i in range(n):
        L.append("agent_step", "agent", {"n": i + 1, "tool": "t"})
    return L


def test_chain_verifies(tmp_path):
    r = _ledger(tmp_path).verify()
    assert r.ok and r.checked == 5


def test_tamper_modes_detected(tmp_path):
    import shutil
    _ledger(tmp_path)
    for mode in ("edit", "delete", "insert"):
        copy = tmp_path / f"{mode}.db"
        shutil.copy(tmp_path / "l.db", copy)
        mocks.tamper_demo(str(copy), 2, mode=mode)
        assert not mocks.MockLedger(copy).verify().ok, mode


def test_merkle_proof_roundtrip(tmp_path):
    L = _ledger(tmp_path, 7)
    p = L.merkle_proof(3)
    assert mocks.verify_proof(p)
    p["leaf"] = "0" * 64
    assert not mocks.verify_proof(p)


def test_pdf_is_wellformed():
    b = pdfmini.make_pdf(["# Head", "line " * 80] * 30)
    assert b.startswith(b"%PDF-1.4") and b.rstrip().endswith(b"%%EOF")

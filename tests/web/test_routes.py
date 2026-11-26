"""Route tests for vai.web (mock backends, offline)."""
import zipfile
import io

from fastapi.testclient import TestClient

from conftest import CID
from vai.web.app import create_app
from vai.web.service import Settings

CONTRACT_ROUTES = {
    ("GET", "/api/cases"), ("GET", "/api/cases/{cid}"), ("POST", "/api/cases/{cid}/run"),
    ("POST", "/api/cases/{cid}/verify"), ("POST", "/api/cases/{cid}/tamper-demo"), ("GET", "/api/cases/{cid}/why"),
    ("POST", "/api/cases/{cid}/approve"), ("GET", "/api/cases/{cid}/report"), ("GET", "/api/cases/{cid}/s63"),
}


def test_all_contract_routes_exist(client):
    have = {(m, r.path) for r in client.app.routes for m in getattr(r, "methods", [])}
    assert CONTRACT_ROUTES <= have


def test_health_and_ui_served(client):
    assert client.get("/api/health").json() == {"ok": True}
    r = client.get("/")
    assert r.status_code == 200 and "Verifiable" in r.text
    assert client.get("/static/app.js").status_code == 200


def test_login_required_when_password_set(tmp_path):
    c = TestClient(create_app(Settings(results_dir=tmp_path / "r", demo_password="s3cret")))
    assert c.get("/api/cases").status_code == 401
    assert c.post("/api/login", json={"password": "wrong"}).status_code == 401
    assert c.post("/api/login", json={"password": "s3cret"}).status_code == 200
    assert c.get("/api/cases").status_code == 200


def test_login_throttle(tmp_path):
    c = TestClient(create_app(Settings(results_dir=tmp_path / "r", demo_password="s3cret")))
    codes = [c.post("/api/login", json={"password": "x"}).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[-1] == 429


def test_two_demo_cases_listed(client):
    ids = [c["id"] for c in client.get("/api/cases").json()]
    assert ids == [CID, "DEMO-PUBLIC-02"]


def test_run_builds_case_and_ledger(done):
    d = done.get(f"/api/cases/{CID}").json()
    assert len(d["steps"]) == 7
    assert {f["technique_id"] for f in d["findings"]} == {"T1078", "T1021", "T1530"}
    assert len(d["events"]) > 12 and d["view"]["stats"]["linked"] == 12
    assert all(l["status"] == "suggested - officer confirms" for l in d["legal"])
    assert "admissible" not in d["view"]["conclusion"]["text"].lower()


def test_second_case_runs(client):
    assert client.post("/api/cases/DEMO-PUBLIC-02/run?wait=true").status_code == 200
    d = client.get("/api/cases/DEMO-PUBLIC-02").json()
    assert {f["technique_id"] for f in d["findings"]} >= {"T1078", "T1003", "T1537"}


def test_verify_ok_then_edit_detected_then_restore(done):
    assert done.post(f"/api/cases/{CID}/verify").json()["ok"] is True
    t = done.post(f"/api/cases/{CID}/tamper-demo", json={"mode": "edit", "step": 3}).json()
    v = done.post(f"/api/cases/{CID}/verify").json()
    assert v["ok"] is False and v["broken_at"] == t["seq"]
    assert done.post(f"/api/cases/{CID}/restore-demo").json()["restored"] is True
    assert done.post(f"/api/cases/{CID}/verify").json()["ok"] is True


def test_delete_middle_step_breaks_chain(done):
    done.post(f"/api/cases/{CID}/tamper-demo", json={"mode": "delete", "step": 3})
    assert done.post(f"/api/cases/{CID}/verify").json()["ok"] is False


def test_delete_last_step_only_completeness_catches_it(done):
    done.post(f"/api/cases/{CID}/tamper-demo", json={"mode": "delete", "step": 7})
    assert done.post(f"/api/cases/{CID}/verify").json()["ok"] is True
    c = done.post(f"/api/cases/{CID}/completeness").json()
    assert c["ok"] is False and 7 in c["missing_steps"]


def test_insert_fake_step_mid_chain_breaks_chain(done):
    done.post(f"/api/cases/{CID}/tamper-demo", json={"mode": "insert", "step": 3})
    assert done.post(f"/api/cases/{CID}/verify").json()["ok"] is False


def test_insert_fake_step_at_end_only_completeness_catches_it(done):
    done.post(f"/api/cases/{CID}/tamper-demo", json={"mode": "insert", "step": 7})
    assert done.post(f"/api/cases/{CID}/verify").json()["ok"] is True
    assert done.post(f"/api/cases/{CID}/completeness").json()["ok"] is False


def test_completeness_ok_on_clean_ledger(done):
    assert done.post(f"/api/cases/{CID}/completeness").json()["ok"] is True


def test_why_has_reasons_records_and_limitations(done):
    items = done.get(f"/api/cases/{CID}/why").json()
    assert len(items) >= 2
    assert all(i["reason"] and i["record_ids"] and i["limitation"] for i in items)


def test_approval_blocked_while_tampered_then_report_after_approval(done):
    assert done.get(f"/api/cases/{CID}/report").status_code == 409          # not approved yet
    done.post(f"/api/cases/{CID}/tamper-demo", json={"mode": "edit", "step": 2})
    assert done.post(f"/api/cases/{CID}/approve", json={"officer": "SI R. Patel"}).status_code == 409
    done.post(f"/api/cases/{CID}/restore-demo")
    a = done.post(f"/api/cases/{CID}/approve", json={"officer": "SI R. Patel"})
    assert a.status_code == 200
    r = done.get(f"/api/cases/{CID}/report")
    assert r.status_code == 200 and r.content.startswith(b"%PDF") and r.content.rstrip().endswith(b"%%EOF")
    assert done.get(f"/api/cases/{CID}").json()["approved"] is True
    assert done.post(f"/api/cases/{CID}/verify").json()["ok"] is True       # approval/report entries keep chain valid


def test_s63_draft_pdf(done):
    r = done.get(f"/api/cases/{CID}/s63")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


def test_actions_before_run_are_refused(client):
    assert client.post(f"/api/cases/{CID}/verify").status_code == 409
    assert client.get(f"/api/cases/{CID}/why").status_code == 409
    assert client.post(f"/api/cases/{CID}/run").status_code in (200, 202)


def test_unknown_case_is_404(client):
    assert client.get("/api/cases/NOPE").status_code == 404


def test_run_twice_needs_fresh(done):
    assert done.post(f"/api/cases/{CID}/run?wait=true").status_code == 409
    assert done.post(f"/api/cases/{CID}/run?wait=true&fresh=true").status_code == 200


def test_evidence_upload_hashes_and_records(client):
    import hashlib
    data = b"hello evidence"
    r = client.post(f"/api/cases/{CID}/evidence", content=data, headers={"X-Filename": "note.txt"})
    assert r.status_code == 200
    j = r.json()
    assert j["file"]["sha256"] == hashlib.sha256(data).hexdigest() and j["ledger_seq"] == 1
    led = client.get(f"/api/cases/{CID}/ledger").json()
    assert led["entries"][0]["kind"] == "evidence"


def test_upload_filename_is_sanitised(client):
    r = client.post(f"/api/cases/{CID}/evidence", content=b"x", headers={"X-Filename": "../../etc/passwd"})
    assert r.status_code == 200 and "/" not in r.json()["file"]["name"] and ".." not in r.json()["file"]["name"]


def test_merkle_proof_valid(done):
    p = done.get(f"/api/cases/{CID}/proof/2").json()
    assert p["valid"] is True


def test_export_package(done):
    r = done.get(f"/api/cases/{CID}/export")
    assert r.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert {"case.json", "ledger_entries.json", "verification.json", "manifest.json", "s63_draft.pdf"} <= set(names)


def test_security_headers(client):
    h = client.get("/").headers
    assert h["x-content-type-options"] == "nosniff" and "default-src" in h["content-security-policy"]

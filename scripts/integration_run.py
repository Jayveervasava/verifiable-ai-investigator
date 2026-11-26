"""End-to-end integration run used by Claude 0 after every zip drop.

Runs both demo cases through the contract APIs:
ingest -> correlate -> timeline -> agent.run -> ledger.verify -> verify_completeness
-> tamper_demo (edit/delete/insert) -> explain -> approve -> report pdf -> s63 pdf

Missing packages are reported as SKIP (not crash), so this works from day 1.
Usage:  python scripts/integration_run.py
Output: results/integration_last.json
"""
from __future__ import annotations

import importlib
import json
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vai.common.models import Case  # noqa: E402

DEMO_CASES = [
    dict(id="FIR-1427/2027", title="Cloud data theft (synthetic)", victim="ABC Finserv Pvt Ltd (fictional)",
         officer="SI R. Patel (fictional)", data_dir="data/sample/fir1427"),
    dict(id="DEMO-2/PUBLIC", title="Public-data case (EVTX-ATTACK-SAMPLES / Stratus Red Team)",
         victim="Public dataset (no real victim)", officer="SI R. Patel (fictional)", data_dir="data/sample/public"),
]


def try_import(name):
    try:
        m = importlib.import_module(name)
        if getattr(m, "__file__", None) is None:  # empty folder = namespace package, not delivered yet
            return None, "package not delivered yet (no __init__.py)"
        return m, None
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def stage(log, name, fn):
    t = time.perf_counter()
    try:
        out = fn()
        log.append(dict(stage=name, status="PASS", ms=round((time.perf_counter() - t) * 1000, 1)))
        return out
    except Exception as e:  # noqa: BLE001
        log.append(dict(stage=name, status="FAIL", error=f"{type(e).__name__}: {e}",
                        trace=traceback.format_exc(limit=3)))
        return None


def run_case(spec, mods):
    log: list[dict] = []
    ev, led, ag, lg = (mods.get(k) for k in ("evidence", "ledger", "agent", "legal"))
    files = sorted(str(p) for p in (ROOT / spec["data_dir"]).glob("**/*") if p.is_file() and p.name != ".gitkeep")
    case = Case(id=spec["id"], title=spec["title"], victim=spec["victim"], officer=spec["officer"])
    if not ev:
        log.append(dict(stage="evidence", status="SKIP", error="vai.evidence not available"))
    elif not files:
        log.append(dict(stage="evidence", status="SKIP", error=f"no files in {spec['data_dir']}"))
    else:
        events = stage(log, "ingest", lambda: ev.ingest(files)) or []
        findings = stage(log, "correlate", lambda: ev.correlate(events)) or []
        findings = stage(log, "timeline", lambda: ev.timeline(findings)) or findings
        case.events, case.findings = events, findings
    if not (led and ag):
        log.append(dict(stage="ledger/agent", status="SKIP", error="vai.ledger or vai.agent not available"))
        return log
    tmp = Path(tempfile.mkdtemp())
    db = str(tmp / "case.db")
    ledger = led.Ledger(db)
    agent = ag.Agent(ledger)
    case2 = stage(log, "agent.run", lambda: agent.run(case)) or case
    v = stage(log, "ledger.verify", lambda: ledger.verify())
    if v is not None and not v.ok:
        log[-1]["status"] = "FAIL"; log[-1]["error"] = f"clean ledger did not verify: {v}"
    stage(log, "verify_completeness", lambda: ledger.verify_completeness(agent.plan(case2), ledger.entries()))
    stage(log, "explain", lambda: agent.explain(case2))
    stage(log, "approve", lambda: agent.approve(case2, spec["officer"]))
    if lg:
        stage(log, "legal.map", lambda: lg.map_techniques([f.technique_id for f in case2.findings]))
        pdf = stage(log, "report_pdf", lambda: lg.case_report_pdf(case2, ledger))
        s63 = stage(log, "s63_pdf", lambda: lg.s63_draft_pdf(case2, ledger))
        for name, b in (("report_pdf", pdf), ("s63_pdf", s63)):
            if b is not None and not bytes(b).startswith(b"%PDF"):
                log.append(dict(stage=name + ".check", status="FAIL", error="output is not a PDF"))
    else:
        log.append(dict(stage="legal", status="SKIP", error="vai.legal not available"))
    for mode in ("edit", "delete", "insert"):
        copy = str(tmp / f"tamper_{mode}.db")
        shutil.copy(db, copy)

        def _t(mode=mode, copy=copy):
            entries = led.Ledger(copy).entries()
            seq = entries[len(entries) // 2].seq if entries else 1
            led.tamper_demo(copy, seq, mode=mode)
            r = led.Ledger(copy).verify()
            if r.ok:
                raise AssertionError(f"tamper mode={mode} NOT detected")
            return r
        stage(log, f"tamper.{mode}", _t)
    return log


def main():
    mods, import_errors = {}, {}
    for p in ("evidence", "ledger", "agent", "legal", "web"):
        m, err = try_import(f"vai.{p}")
        if m:
            mods[p] = m
        else:
            import_errors[p] = err
    if "web" in mods:
        try:
            from fastapi.testclient import TestClient
            app = getattr(mods["web"], "app", None) or importlib.import_module("vai.web.app").app
            r = TestClient(app).get("/api/cases")
            import_errors["web_smoke"] = f"GET /api/cases -> {r.status_code}"
        except Exception as e:  # noqa: BLE001
            import_errors["web_smoke"] = f"FAIL {type(e).__name__}: {e}"
    report = dict(packages_loaded=sorted(mods), import_notes=import_errors,
                  cases={c["id"]: run_case(c, mods) for c in DEMO_CASES})
    out = ROOT / "results" / "integration_last.json"
    out.write_text(json.dumps(report, indent=2))
    for cid, log in report["cases"].items():
        print(f"\n== {cid}")
        for s in log:
            print(f"  {s['status']:4}  {s['stage']}  {s.get('error', '')}")
    print("\nimport notes:", json.dumps(import_errors, indent=2))
    fails = sum(s["status"] == "FAIL" for log in report["cases"].values() for s in log)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()

"""Case service: all the logic behind the routes (run, verify, tamper demo, approve, reports, export)."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import adapters, demo_data
from .models import Case, dump, iso

TECH = {"T1078": "Valid Accounts", "T1021": "Remote Services", "T1530": "Data from Cloud Storage",
        "T1003": "OS Credential Dumping", "T1537": "Transfer Data to Cloud Account"}


class ServiceError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Settings:
    results_dir: Path = field(default_factory=lambda: Path(os.getenv("VAI_RESULTS_DIR", "results/web")))
    demo_password: str = field(default_factory=lambda: os.getenv("DEMO_PASSWORD", ""))
    max_upload_mb: int = field(default_factory=lambda: int(os.getenv("VAI_MAX_UPLOAD_MB", "20")))


@dataclass
class CaseState:
    id: str
    meta: dict
    db: Path
    case: Case
    status: str = "new"  # new | running | done | error
    error: str | None = None
    tampered_db: Path | None = None
    tamper_info: dict | None = None
    last_verify: dict | None = None
    last_completeness: dict | None = None
    files: list = field(default_factory=list)
    approved_by: str | None = None
    report_ledgered: bool = False
    lock: threading.RLock = field(default_factory=threading.RLock)


def _pd(x):
    return x if isinstance(x, dict) else dump(x)


class Service:
    def __init__(self, settings: Settings):
        self.s = settings
        self.root = Path(settings.results_dir)
        for d in ("ledgers", "cases", "uploads", "archive", "reports", "verify"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        paths = demo_data.generate(self.root / "demo_evidence")
        # Claude 0: prefer the real sample data from vai.evidence (Claude 1) when present
        _repo = Path(__file__).resolve().parents[2] / "data" / "sample"
        for _cid, _dir in (("FIR-1427-2027", "case_fir_1427"), ("DEMO-PUBLIC-02", "case_public")):
            _real = sorted(str(f) for f in (_repo / _dir).glob("*")
                           if f.is_file() and not f.name.startswith("_") and f.suffix != ".md")
            if _real:
                paths[_cid] = _real
        self.cases: dict[str, CaseState] = {}
        for cid, meta in demo_data.CASES.items():
            st = CaseState(id=cid, meta=meta, db=self.root / "ledgers" / f"{cid}.db", case=self._blank(cid))
            for p in paths[cid]:
                st.files.append(self._file_rec(p, "demo"))
            self._load(st)
            self.cases[cid] = st
        B = adapters.backends()
        self._save("config.json", {"backends": B.using, "models": __import__("vai.web.models", fromlist=["x"]).SOURCE,
                                   "login_required": bool(settings.demo_password), "cases": list(self.cases),
                                   "max_upload_mb": settings.max_upload_mb, "created": _now()})

    # ------------------------------------------------------------------ helpers
    def _blank(self, cid) -> Case:
        m = demo_data.CASES[cid]
        return Case(id=cid, title=m["title"], victim=m["victim"], officer=m["officer"])

    def _save(self, name, obj):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")

    def _file_rec(self, path: Path, kind: str) -> dict:
        data = Path(path).read_bytes()
        return {"name": Path(path).name, "path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data), "kind": kind, "ledgered": False, "seq": None, "parsed": None, "added": _now()}

    def _persist(self, st: CaseState):
        self._save(f"cases/{st.id}.json", {"case": dump(st.case), "status": st.status, "files": st.files,
                                           "approved_by": st.approved_by, "report_ledgered": st.report_ledgered})

    def _load(self, st: CaseState):
        p = self.root / "cases" / f"{st.id}.json"
        if not (p.exists() and st.db.exists()):
            return
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            st.case = Case.model_validate(d["case"])
            st.status = "done" if d.get("status") == "done" else "new"
            st.files, st.approved_by, st.report_ledgered = d["files"], d.get("approved_by"), d.get("report_ledgered", False)
        except Exception:
            pass

    def _state(self, cid) -> CaseState:
        if cid not in self.cases:
            raise ServiceError(404, f"Unknown case {cid}")
        return self.cases[cid]

    def _ledger(self, st: CaseState, original=False):
        db = st.db if original or not st.tampered_db else st.tampered_db
        return adapters.backends().Ledger(str(db))

    def _agent(self, st: CaseState, ledger):
        return adapters.backends().Agent(ledger)

    def _need_done(self, st):
        if st.status != "done":
            raise ServiceError(409, "Run the investigation first.")

    def _map(self, st, ledger, plan):
        """plan step n -> ledger entry; plus unplanned agent-step entries."""
        entries = ledger.entries()
        ag = [e for e in entries if e.kind == "agent_step"]
        ns = [p["n"] for p in plan]
        n2e, extras = {}, []
        po = getattr(ledger, "payload_of", None)
        for i, e in enumerate(ag):
            n = (po(e.seq) or {}).get("n") if po else (ns[i] if i < len(ns) else None)
            if n in ns and n not in n2e:
                n2e[n] = e
            else:
                extras.append(e)
        return entries, n2e, extras

    def _plan(self, st, ledger):
        return [_pd(p) for p in self._agent(st, ledger).plan(st.case)]

    def _reset_checks(self, st):
        st.last_verify = st.last_completeness = None

    # ------------------------------------------------------------------ views
    def list_cases(self):
        out = []
        for st in self.cases.values():
            c = st.case
            out.append({"id": c.id, "title": c.title, "victim": c.victim, "officer": c.officer, "approved": c.approved,
                        "status": st.status, "note": st.meta["note"], "opened": st.meta["opened"],
                        "techniques": sorted({f.technique_id for f in c.findings}),
                        "records": len(c.events), "files": len(st.files)})
        return out

    def get_case(self, cid, events="all"):
        st = self._state(cid)
        with st.lock:
            d = dump(st.case)
            if events == "linked":
                keep = {i for f in st.case.findings for i in f.event_ids}
                d["events"] = [e for e in d["events"] if e["id"] in keep]
            elif events == "none":
                d["events"] = []
            d["view"] = self._view(st)
            return d

    def _view(self, st: CaseState):
        ledger = self._ledger(st) if st.db.exists() else None
        plan_raw = self._plan(st, ledger or adapters.backends().Ledger(str(st.db)))
        entries, n2e, extras = ([], {}, []) if ledger is None else self._map(st, ledger, plan_raw)
        v, c = st.last_verify, st.last_completeness
        broken = v["broken_at"] if v and not v["ok"] else None
        plan = []
        for p in plan_raw:
            e = n2e.get(p["n"])
            if e is None:
                state = "missing" if st.status == "done" else "pending"
            elif v is None:
                state = "recorded"
            elif v["ok"]:
                state = "verified"
            elif broken is None or e.seq < broken:
                state = "verified"
            elif e.seq == broken:
                state = "broken"
            else:
                state = "after_break"
            plan.append({**p, "state": state, "seq": e.seq if e else None, "hash": e.hash if e else None})
        step_of = {e.seq: n for n, e in n2e.items()}
        ent = [{**dump(e), "step": step_of.get(e.seq), "unplanned": e in extras} for e in entries]
        if v is None:
            custody = ("unchecked", "Custody not checked")
        elif not v["ok"]:
            custody = ("broken", "Custody broken")
        elif c is not None and not c["ok"]:
            custody = ("incomplete", "Steps missing or added")
        elif c is not None:
            custody = ("ok", "Custody verified")
        else:
            custody = ("chain", "Chain verified (completeness not checked)")
        concl = next((s for s in st.case.steps if s.tool == "conclude"), None)
        order = {"high": 2, "medium": 1, "low": 0}
        conf = min((f.confidence for f in st.case.findings), key=lambda x: order[x]) if st.case.findings else None
        by_key = {}
        for m in st.case.legal:
            r = by_key.setdefault((m.act, m.section), {"offence": m.offence, "act": m.act, "section": m.section,
                                                       "reason": m.reason, "url": m.source_url, "techniques": []})
            if m.technique_id not in r["techniques"]:
                r["techniques"].append(m.technique_id)
        legal = list(by_key.values())
        root = None
        try:
            root = ledger.merkle_root() if ledger and hasattr(ledger, "merkle_root") else (
                ledger.merkle_proof(entries[0].seq)["root"] if entries else None)
        except Exception:
            pass
        linked = {i for f in st.case.findings for i in f.event_ids}
        B = adapters.backends()
        return {
            "status": st.status, "error": st.error, "tampered": st.tampered_db is not None,
            "tamper_info": st.tamper_info, "custody": {"state": custody[0], "label": custody[1]},
            "approved_by": st.approved_by, "plan": plan, "entries": ent, "merkle_root": root,
            "verification": v, "completeness": c,
            "stats": {"records": len(st.case.events) if st.case.events else None, "linked": len(linked),
                      "techniques": len({f.technique_id for f in st.case.findings}), "steps_total": len(plan),
                      "steps_verified": sum(p["state"] == "verified" for p in plan) if v else None},
            "conclusion": {"text": concl.reasoning if concl else None, "confidence": conf},
            "legal": legal, "technique_names": TECH, "files": st.files, "note": st.meta["note"],
            "opened": st.meta["opened"], "backends": {**B.using},
        }

    # ------------------------------------------------------------------ run
    def run(self, cid, wait=False, fresh=False):
        st = self._state(cid)
        with st.lock:
            if st.tampered_db:
                raise ServiceError(409, "Restore the original ledger before running again.")
            if st.status == "running":
                raise ServiceError(409, "Investigation is already running.")
            if st.status == "done" and not fresh:
                raise ServiceError(409, "Already done. Use 'Run again (new ledger)' to start a fresh ledger.")
            if st.db.exists():  # keep old ledger, never delete it
                shutil.move(str(st.db), str(self.root / "archive" / f"{cid}.{datetime.now():%Y%m%d-%H%M%S}.db"))
            for f in st.files:
                f["ledgered"], f["seq"] = False, None
            st.case, st.status, st.error, st.approved_by, st.report_ledgered = self._blank(cid), "running", None, None, False
            self._reset_checks(st)
        if wait:
            self._worker(st)
        else:
            threading.Thread(target=self._worker, args=(st,), daemon=True).start()

    def _worker(self, st: CaseState):
        B = adapters.backends()
        try:
            ledger = B.Ledger(str(st.db))
            events = []
            for f in st.files:
                evs = B.ingest([f["path"]])
                f["parsed"] = len(evs)
                if not f["ledgered"]:
                    e = ledger.append("evidence", "intake", {"file": f["name"], "sha256": f["sha256"],
                                                             "bytes": f["bytes"], "parsed_events": len(evs)})
                    f["ledgered"], f["seq"] = True, e.seq
                events += evs
            st.case.events = events
            st.case = B.Agent(ledger, None).run(st.case)
            with st.lock:
                st.status = "done"
                self._persist(st)
        except Exception as ex:  # shown in the UI
            st.status, st.error = "error", f"{type(ex).__name__}: {ex}"

    # ------------------------------------------------------------------ checks
    def verify(self, cid):
        st = self._state(cid)
        if not st.db.exists():
            raise ServiceError(409, "Nothing to verify yet. Run the investigation first.")
        with st.lock:
            res = _pd(self._ledger(st).verify())
            res.update(at=_now(), on="simulated-tamper copy" if st.tampered_db else "original ledger")
            st.last_verify = res
            self._save(f"verify/{st.id}_verify_{datetime.now():%H%M%S%f}.json", res)
            return res

    def completeness(self, cid):
        st = self._state(cid)
        self._need_done(st)
        with st.lock:
            ledger = self._ledger(st)
            res = _pd(ledger.verify_completeness(self._plan(st, ledger), ledger.entries()))
            res.update(at=_now(), on="simulated-tamper copy" if st.tampered_db else "original ledger")
            st.last_completeness = res
            self._save(f"verify/{st.id}_completeness_{datetime.now():%H%M%S%f}.json", res)
            return res

    def tamper(self, cid, mode, step=None, seq=None):
        st = self._state(cid)
        self._need_done(st)
        if mode not in ("edit", "delete", "insert"):
            raise ServiceError(422, "mode must be edit, delete or insert")
        with st.lock:
            if st.tampered_db:
                raise ServiceError(409, "Already tampered (demo copy). Restore the original first.")
            ledger = self._ledger(st, original=True)
            plan = self._plan(st, ledger)
            _, n2e, _ = self._map(st, ledger, plan)
            if seq is None:
                step = step or 3
                if step not in n2e:
                    raise ServiceError(422, f"No step {step}")
                seq = n2e[step].seq
            tdb = self.root / "ledgers" / f"{cid}.tampered.db"
            if tdb.exists():
                shutil.move(str(tdb), str(self.root / "archive" / f"{cid}.tampered.{datetime.now():%H%M%S%f}.db"))
            shutil.copy2(st.db, tdb)
            try:
                adapters.backends().tamper_demo(str(tdb), seq, mode=mode)
            except Exception as ex:
                shutil.move(str(tdb), str(self.root / "archive" / f"{cid}.failed-tamper.db"))
                raise ServiceError(422, f"Tamper demo failed: {ex}")
            st.tampered_db, st.tamper_info = tdb, {"mode": mode, "seq": seq, "step": step}
            self._reset_checks(st)
            return {"mode": mode, "seq": seq, "step": step, "note": "Only a demo COPY was changed. The real ledger is untouched."}

    def restore(self, cid):
        st = self._state(cid)
        with st.lock:
            if st.tampered_db:
                shutil.move(str(st.tampered_db), str(self.root / "archive" / f"{cid}.tampered.{datetime.now():%H%M%S%f}.db"))
            st.tampered_db = st.tamper_info = None
            self._reset_checks(st)
        return {"restored": True}

    # ------------------------------------------------------------------ AI explain / approve / docs
    def why(self, cid):
        st = self._state(cid)
        self._need_done(st)
        return [_pd(x) for x in self._agent(st, self._ledger(st)).explain(st.case)]

    def approve(self, cid, officer):
        st = self._state(cid)
        self._need_done(st)
        officer = (officer or st.case.officer).strip()[:80]
        with st.lock:
            if st.tampered_db:
                raise ServiceError(409, "Custody is not verified (demo tamper active). Restore the original ledger first.")
            ledger = self._ledger(st, original=True)
            v = ledger.verify()
            c = ledger.verify_completeness(self._plan(st, ledger), ledger.entries())
            if not v.ok or not c.ok:
                raise ServiceError(409, "Cannot approve: the ledger failed verification or is incomplete.")
            if st.case.approved:
                raise ServiceError(409, "Already approved.")
            res = self._agent(st, ledger).approve(st.case, officer)
            if res is not None and hasattr(res, "approved"):
                st.case = res
            st.case.approved, st.approved_by = True, officer
            self._reset_checks(st)
            self._persist(st)
            return {"approved": True, "officer": officer}

    def report(self, cid) -> bytes:
        st = self._state(cid)
        self._need_done(st)
        if not st.case.approved:
            raise ServiceError(409, "Officer approval is required before the report is final.")
        with st.lock:
            ledger = self._ledger(st)
            pdf = adapters.backends().case_report_pdf(st.case, ledger)
            (self.root / "reports" / f"{cid}_report.pdf").write_bytes(pdf)
            if not st.report_ledgered and not st.tampered_db:
                ledger.append("report", "system", {"report_sha256": hashlib.sha256(pdf).hexdigest(), "bytes": len(pdf)})
                st.report_ledgered = True
                self._persist(st)
            return pdf

    def s63(self, cid) -> bytes:
        st = self._state(cid)
        self._need_done(st)
        pdf = adapters.backends().s63_draft_pdf(st.case, self._ledger(st))
        (self.root / "reports" / f"{cid}_s63_draft.pdf").write_bytes(pdf)
        return pdf

    # ------------------------------------------------------------------ ledger / proof / export
    def ledger_view(self, cid):
        st = self._state(cid)
        return self.get_case(cid, events="none")["view"] if st.db.exists() else {"entries": [], "status": st.status,
                                                                                  "merkle_root": None, "verification": None}

    def proof(self, cid, seq):
        st = self._state(cid)
        ledger = self._ledger(st)
        if not hasattr(ledger, "merkle_proof"):
            raise ServiceError(501, "Ledger has no merkle_proof")
        try:
            p = ledger.merkle_proof(seq)
        except Exception:
            raise ServiceError(404, f"No ledger entry {seq}")
        return {"proof": p, "valid": bool(adapters.backends().verify_proof(p))}

    def export(self, cid) -> bytes:
        st = self._state(cid)
        self._need_done(st)
        if st.tampered_db:
            raise ServiceError(409, "Restore the original ledger before exporting.")
        ledger = self._ledger(st)
        v = _pd(ledger.verify())
        c = _pd(ledger.verify_completeness(self._plan(st, ledger), ledger.entries()))
        files = {
            "case.json": json.dumps(dump(st.case), indent=2),
            "ledger_entries.json": json.dumps([dump(e) for e in ledger.entries()], indent=2),
            "verification.json": json.dumps({"chain": v, "completeness": c, "at": _now()}, indent=2),
            "evidence_hashes.json": json.dumps([{k: f[k] for k in ("name", "sha256", "bytes")} for f in st.files], indent=2),
            "s63_draft.pdf": self.s63(cid),
        }
        if hasattr(ledger, "merkle_root"):
            files["merkle_root.txt"] = ledger.merkle_root()
        if st.case.approved:
            files["report.pdf"] = self.report(cid)
        manifest = {n: hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest() for n, b in files.items()}
        readme = ("Evidence package (demo, synthetic data).\nRe-verify: recompute SHA-256 of each file against manifest.json, "
                  "then recompute the hash chain in ledger_entries.json.\nThis package is verifiable; admissibility is for the court.\n")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, b in files.items():
                z.writestr(n, b)
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
            z.writestr("README.txt", readme)
        return buf.getvalue()

    # ------------------------------------------------------------------ evidence upload
    def upload(self, cid, filename, data: bytes):
        st = self._state(cid)
        if len(data) > self.s.max_upload_mb * 1024 * 1024:
            raise ServiceError(413, f"File larger than {self.s.max_upload_mb} MB")
        if not data:
            raise ServiceError(422, "Empty file")
        name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename or "upload.bin").name)[:100] or "upload.bin"
        with st.lock:
            if st.status == "running":
                raise ServiceError(409, "Wait until the run finishes.")
            if st.tampered_db:
                raise ServiceError(409, "Restore the original ledger first.")
            folder = self.root / "uploads" / cid
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / f"{datetime.now():%Y%m%d-%H%M%S}_{name}"
            path.write_bytes(data)
            rec = self._file_rec(path, "upload")
            rec["name"] = name
            events = adapters.backends().ingest([str(path)])
            rec["parsed"] = len(events)
            ledger = adapters.backends().Ledger(str(st.db))
            e = ledger.append("evidence", "intake", {"file": name, "sha256": rec["sha256"], "bytes": rec["bytes"],
                                                     "parsed_events": len(events), "source": "officer upload"})
            rec["ledgered"], rec["seq"] = True, e.seq
            st.files.append(rec)
            self._reset_checks(st)
            self._persist(st)
            msg = ("Hashed and recorded in the ledger. Run again (new ledger) to include it in the analysis."
                   if st.status == "done" else "Hashed and recorded in the ledger. It will be used in the next run.")
            if not events:
                msg += " No events could be read from this format yet (parsers belong to vai.evidence)."
            return {"file": rec, "ledger_seq": e.seq, "message": msg}

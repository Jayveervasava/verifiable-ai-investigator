"""Mock implementations of the other packages (evidence, ledger, agent, legal).

They follow the CONTRACT so the web layer works before the real packages exist.
adapters.py automatically prefers the real packages when they are importable.
The mock ledger is a REAL hash chain (sqlite), so tamper detection is genuine.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import pdfmini
from .models import AgentStep, Case, Event, Finding, LedgerEntry, LegalMatch, VerifyResult, dump, iso

GENESIS = "0" * 64
_LOCK = threading.RLock()


def canon(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha(x) -> str:
    return hashlib.sha256(x.encode() if isinstance(x, str) else x).hexdigest()


def entry_hash(seq, ts, kind, actor, payload_hash, prev) -> str:
    return sha(f"{seq}|{ts}|{kind}|{actor}|{payload_hash}|{prev}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ----------------------------------------------------------------------------- ledger
def _levels(leaves: list[str]) -> list[list[str]]:
    lv = [list(leaves)]
    while len(lv[-1]) > 1:
        cur, nxt = lv[-1], []
        for i in range(0, len(cur), 2):
            nxt.append(sha(cur[i] + (cur[i + 1] if i + 1 < len(cur) else cur[i])))
        lv.append(nxt)
    return lv


def verify_proof(p: dict) -> bool:
    h = p["leaf"]
    for s in p["path"]:
        h = sha(h + s["hash"]) if s["side"] == "right" else sha(s["hash"] + h)
    return h == p["root"]


class MockLedger:
    """Hash-chained, append-only log stored in sqlite."""

    def __init__(self, db):
        self.db = str(db)
        Path(self.db).parent.mkdir(parents=True, exist_ok=True)
        with self._c() as c:
            c.execute("CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, ts TEXT, kind TEXT, "
                      "actor TEXT, payload TEXT, payload_hash TEXT, prev_hash TEXT, hash TEXT)")

    def _c(self):
        return sqlite3.connect(self.db, timeout=10)

    @staticmethod
    def _entry(r) -> LedgerEntry:
        return LedgerEntry(seq=r[0], ts=r[1], kind=r[2], actor=r[3], payload_hash=r[5], prev_hash=r[6], hash=r[7])

    def append(self, kind, actor, payload) -> LedgerEntry:
        with _LOCK, self._c() as c:
            last = c.execute("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
            ts, pj = now_iso(), canon(payload)
            ph = sha(pj)
            h = entry_hash(seq, ts, kind, actor, ph, prev)
            c.execute("INSERT INTO entries VALUES (?,?,?,?,?,?,?,?)", (seq, ts, kind, actor, pj, ph, prev, h))
            return LedgerEntry(seq=seq, ts=ts, kind=kind, actor=actor, payload_hash=ph, prev_hash=prev, hash=h)

    def entries(self) -> list[LedgerEntry]:
        with self._c() as c:
            return [self._entry(r) for r in c.execute("SELECT * FROM entries ORDER BY seq")]

    def payload_of(self, seq: int):
        with self._c() as c:
            r = c.execute("SELECT payload FROM entries WHERE seq=?", (seq,)).fetchone()
        try:
            return json.loads(r[0]) if r else None
        except Exception:
            return None

    def verify(self) -> VerifyResult:
        with self._c() as c:
            rows = c.execute("SELECT * FROM entries ORDER BY seq").fetchall()
        prev, expected, checked = GENESIS, 1, 0
        for r in rows:
            seq, ts, kind, actor, pj, ph, pv, h = r
            if (seq != expected or sha(pj) != ph or pv != prev
                    or entry_hash(seq, ts, kind, actor, ph, pv) != h):
                return VerifyResult(ok=False, checked=checked, broken_at=expected if seq != expected else seq)
            prev, expected, checked = h, expected + 1, checked + 1
        return VerifyResult(ok=True, checked=checked, broken_at=None)

    def verify_completeness(self, plan, entries) -> VerifyResult:
        chain = self.verify()
        planned = [int(_g(s, "n")) for s in plan]
        present, extra_seq = set(), None
        for e in entries:
            if e.kind == "agent_step":
                n = (self.payload_of(e.seq) or {}).get("n")
                if n in planned:
                    present.add(n)
                elif extra_seq is None:
                    extra_seq = e.seq
        missing = [n for n in planned if n not in present]
        ok = chain.ok and not missing and extra_seq is None
        broken = chain.broken_at if chain.broken_at is not None else extra_seq
        return VerifyResult(ok=ok, checked=chain.checked, broken_at=broken, missing_steps=missing)

    def merkle_root(self) -> str:
        hs = [e.hash for e in self.entries()]
        return _levels(hs)[-1][0] if hs else sha("")

    def merkle_proof(self, seq: int) -> dict:
        es = self.entries()
        hs = [e.hash for e in es]
        idx = next(i for i, e in enumerate(es) if e.seq == seq)
        lv, path, leaf = _levels(hs), [], hs[idx]
        for level in lv[:-1]:
            sib = idx ^ 1
            path.append({"hash": level[sib] if sib < len(level) else level[idx],
                         "side": "right" if idx % 2 == 0 else "left"})
            idx //= 2
        return {"seq": seq, "leaf": leaf, "path": path, "root": lv[-1][0]}


def _g(o, k, default=None):
    return o.get(k, default) if isinstance(o, dict) else getattr(o, k, default)


def tamper_demo(db, seq: int, mode: str = "edit") -> dict:
    """Damage a COPY of the ledger on purpose. modes: edit | delete | insert (insert AFTER seq)."""
    with _LOCK, sqlite3.connect(str(db), timeout=10) as c:
        if mode == "edit":
            r = c.execute("SELECT payload FROM entries WHERE seq=?", (seq,)).fetchone()
            if not r:
                raise ValueError(f"no entry {seq}")
            p = json.loads(r[0])
            p["_edited"] = "changed after saving"
            c.execute("UPDATE entries SET payload=? WHERE seq=?", (canon(p), seq))
        elif mode == "delete":
            if c.execute("DELETE FROM entries WHERE seq=?", (seq,)).rowcount == 0:
                raise ValueError(f"no entry {seq}")
        elif mode == "insert":
            prev = c.execute("SELECT hash FROM entries WHERE seq=?", (seq,)).fetchone()
            if not prev:
                raise ValueError(f"no entry {seq}")
            for (s,) in c.execute("SELECT seq FROM entries WHERE seq>? ORDER BY seq DESC", (seq,)).fetchall():
                c.execute("UPDATE entries SET seq=? WHERE seq=?", (s + 1, s))
            payload = {"n": 0, "tool": "forged_step", "input_hash": sha("x"), "output_hash": sha("y"),
                       "reasoning": "inserted by attacker"}
            pj, ts, new = canon(payload), now_iso(), seq + 1
            ph = sha(pj)
            c.execute("INSERT INTO entries VALUES (?,?,?,?,?,?,?,?)",
                      (new, ts, "agent_step", "agent", pj, ph, prev[0],
                       entry_hash(new, ts, "agent_step", "agent", ph, prev[0])))
        else:
            raise ValueError("mode must be edit, delete or insert")
    return {"mode": mode, "seq": seq}


# ----------------------------------------------------------------------------- evidence
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                              "169.254.0.0/16")]


def is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(a in n for n in _PRIVATE)


def ingest(paths) -> list[Event]:
    """Mock: reads Event-format JSONL. Other formats return nothing (real parsers are vai.evidence's job)."""
    out = []
    for p in paths:
        p = Path(p)
        if p.suffix.lower() not in (".jsonl", ".json", ".ndjson"):
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                out.append(Event(**json.loads(line)))
            except Exception:
                continue
    return out


def _familiar(events) -> set:
    days: dict = {}
    for e in events:
        days.setdefault((e.user, e.ip), set()).add(iso(e.ts_utc)[:10])
    return {k for k, v in days.items() if len(v) >= 2}


def _human(n: int) -> str:
    return f"{n / 2 ** 30:.1f} GiB" if n >= 2 ** 30 else f"{n / 2 ** 20:.1f} MiB"


def _bytes(e) -> int:
    m = re.search(r"bytes=(\d+)", e.action)
    return int(m.group(1)) if m else 0


def _rule(e, fam):
    a, ext = e.action, is_external(e.ip) and (e.user, e.ip) not in fam
    if ext and e.source == "windows" and a.startswith(("logon_success", "rdp_session_start")):
        return "T1078"
    if ext and e.source == "aws" and a.startswith("sts:GetCallerIdentity"):
        return "T1078"
    if ext and e.source == "linux" and (a.startswith("ssh_login_success") or (a.startswith("file_read") and ".aws/" in a)):
        return "T1021"
    if a.startswith("smb_admin_share_access"):
        return "T1021"
    if ext and e.source == "aws" and a.startswith(("s3:GetObject", "s3:ListBucket")):
        return "T1530"
    if a.startswith("lsass_access"):
        return "T1003"
    if a.startswith("ec2:ModifySnapshotAttribute"):
        return "T1537"
    return None


def _title(t, evs) -> str:
    u, ip, hosts = evs[0].user, evs[0].ip, sorted({e.host for e in evs})
    if t == "T1078":
        return f"Valid account '{u}' used from IP {ip} not seen in its earlier activity"
    if t == "T1021":
        if any(e.action.startswith("ssh_login") for e in evs):
            return f"SSH to {', '.join(hosts)} as '{u}' from {ip}, then cloud credential files read"
        return f"Admin share (SMB) access on {', '.join(hosts)} as '{u}'"
    if t == "T1530":
        tot = sum(_bytes(e) for e in evs)
        return f"Cloud storage access by '{u}' from {ip}: {len(evs)} requests, {_human(tot)} downloaded"
    if t == "T1003":
        return f"Credential dumping indicator (LSASS access) on {', '.join(hosts)} by '{u}'"
    if t == "T1537":
        return f"Cloud snapshot shared outside the account by '{u}'"
    return f"{t} indicator"


def correlate(events) -> list[Finding]:
    fam = _familiar(events)
    hits: dict = {}
    for e in sorted(events, key=lambda x: iso(x.ts_utc)):
        t = _rule(e, fam)
        if t:
            hits.setdefault(t, []).append(e)
    user_sources: dict = {}
    for evs in hits.values():
        for e in evs:
            user_sources.setdefault(e.user, set()).add(e.source)
    out = []
    for t, evs in sorted(hits.items(), key=lambda kv: iso(kv[1][0].ts_utc)):
        multi = max(len(user_sources[e.user]) for e in evs) >= 2
        conf = "high" if multi and len(evs) >= 2 else "medium" if multi or len(evs) >= 2 else "low"
        out.append(Finding(id=f"F-{len(out) + 1}", technique_id=t, title=_title(t, evs),
                           event_ids=[e.id for e in evs], confidence=conf))
    return out


def timeline(findings) -> list[Finding]:
    return sorted(findings, key=lambda f: int(str(f.id).split("-")[-1]))


# ----------------------------------------------------------------------------- legal
_IT = "IT Act 2000"
_URL = "https://www.indiacode.nic.in/"
_S66 = ("Unauthorised access / computer-related offence", "66")
_S66C = ("Identity theft (fraudulent use of password)", "66C")
_S43B = ("Downloading or copying data without permission", "43(b)")
_LEGAL = {"T1078": [_S66C, _S66], "T1021": [_S66], "T1530": [_S43B, _S66],
          "T1003": [_S43B, _S66], "T1537": [_S43B, _S66]}


def map_techniques(ids) -> list[LegalMatch]:
    out = []
    for t in ids:
        for offence, sec in _LEGAL.get(t, []):
            out.append(LegalMatch(technique_id=t, offence=offence, act=_IT, section=sec,
                                  reason=f"Technique {t} was observed in the evidence; whether this section applies is for the officer.",
                                  source_url=_URL, status="suggested - officer confirms"))
    return out


def _root(ledger) -> str:
    try:
        return ledger.merkle_root()
    except Exception:
        try:
            return ledger.merkle_proof(ledger.entries()[0].seq)["root"]
        except Exception:
            return "unavailable"


def _doc(case, ledger, title, draft_note) -> list[str]:
    v = ledger.verify()
    L = [f"# {title}", draft_note, "",
         f"Case: {case.title}", f"Victim: {case.victim}", f"Officer: {case.officer}",
         f"Approved by officer: {'yes' if case.approved else 'NO (not final)'}",
         f"Generated: {now_iso()}", "",
         "# Findings (each lists the record IDs it rests on)"]
    for f in case.findings:
        L += [f"- [{f.confidence}] {f.technique_id}: {f.title}", f"    Records: {', '.join(f.event_ids)}"]
    L += ["", "# Suggested legal sections (suggested - officer confirms)"]
    seen = set()
    for m in case.legal:
        if (m.act, m.section) not in seen:
            seen.add((m.act, m.section))
            L.append(f"- {m.act} s.{m.section}: {m.offence} (technique {m.technique_id})")
    L += ["", "# AI steps recorded in the custody ledger"]
    for s in case.steps:
        L.append(f"- Step {s.n} [{s.tool}] ledger entries {', '.join(s.record_ids)}; output hash {s.output_hash[:16]}...")
    L += ["", "# Custody ledger", f"Entries: {len(ledger.entries())}", f"Merkle root: {_root(ledger)}",
          f"Chain check at generation: {'intact' if v.ok else 'BROKEN at entry ' + str(v.broken_at)}",
          "", "# Limitations",
          "- Automated, rule-based reading of the supplied records. It does not establish who used an account.",
          "- Legal sections are suggestions only. The officer decides.",
          "- This record is verifiable (hash-chained). Whether a court admits it is for the court."]
    return L


def case_report_pdf(case, ledger) -> bytes:
    return pdfmini.make_pdf(_doc(case, ledger, "Investigation report (demo, synthetic data)",
                                 "Prepared by the Verifiable AI Investigator demo. Fictional case."))


def s63_draft_pdf(case, ledger) -> bytes:
    L = _doc(case, ledger, "DRAFT - Certificate under Section 63, BSA 2023 (not signed)",
             "Draft text only. The certificate format required by the Act is for the officer and legal team to finalise.")
    L += ["", "# Draft statement", f"I, {case.officer}, certify that the electronic records listed for case {case.id} "
          "were processed by this system and that their hashes are recorded in the ledger above.",
          "Signature: PENDING OFFICER"]
    return pdfmini.make_pdf(L)


# ----------------------------------------------------------------------------- agent
_PLAN = [
    (1, "load_and_hash", "Load and hash all evidence records"),
    (2, "normalise", "Normalise sources to one event format"),
    (3, "correlate", "Link events by user, IP and credential"),
    (4, "timeline_mitre", "Build timeline and map MITRE ATT&CK"),
    (5, "map_legal", "Map techniques to IT Act sections (suggested)"),
    (6, "conclude", "Write conclusion with reasons and limits"),
    (7, "draft_documents", "Draft Section 63 certificate (report follows approval)"),
]
_KEY_RE = re.compile(r"AKIA[A-Z0-9]{16}")


class MockAgent:
    def __init__(self, ledger, llm=None):
        self.ledger, self.llm = ledger, llm

    def plan(self, case) -> list[dict]:
        return [{"n": n, "tool": t, "description": d} for n, t, d in _PLAN]

    # -- helpers
    def _step(self, n, tool, inp, out, reasoning):
        payload = {"n": n, "tool": tool, "input_hash": sha(canon(inp)), "output_hash": sha(canon(out)),
                   "reasoning": reasoning}
        e = self.ledger.append("agent_step", "agent", payload)
        return AgentStep(n=n, tool=tool, input_hash=payload["input_hash"], output_hash=payload["output_hash"],
                         reasoning=reasoning, record_ids=[str(e.seq)])

    def _conclusion(self, case):
        fs = case.findings
        evs = {e.id: e for e in case.events}
        linked = [evs[i] for f in fs for i in f.event_ids if i in evs]
        if not fs or not linked:
            return "No linked suspicious activity was found in the supplied records.", "low"
        user = max({e.user for e in linked}, key=lambda u: sum(e.user == u for e in linked))
        mine = sorted((e for e in linked if e.user == user), key=lambda e: iso(e.ts_utc))
        srcs = sorted({e.source for e in mine})
        t0, t1 = datetime.fromisoformat(iso(mine[0].ts_utc).replace("Z", "+00:00")), \
            datetime.fromisoformat(iso(mine[-1].ts_utc).replace("Z", "+00:00"))
        mins = max(1, round((t1 - t0).total_seconds() / 60))
        total = sum(_bytes(e) for e in linked if e.source == "aws")
        txt = (f"The same account ('{user}') is active across {len(srcs)} source(s) ({', '.join(srcs)}) within about "
               f"{mins} minutes, starting from IP {mine[0].ip}, which does not appear in its earlier activity. "
               f"{len({i for f in fs for i in f.event_ids})} linked events, techniques: "
               f"{', '.join(sorted({f.technique_id for f in fs}))}.")
        if total:
            txt += f" Cloud downloads in these records total {_human(total)} ({total:,} bytes)."
        txt += " This is an automated, rule-based reading of the supplied records; it does not establish who used the account."
        order = {"high": 2, "medium": 1, "low": 0}
        return txt, min((f.confidence for f in fs), key=lambda c: order[c])

    # -- contract
    def run(self, case):
        from . import adapters
        B = adapters.backends()
        delay = float(os.getenv("VAI_STEP_DELAY", "0.7"))
        recs = [dump(e) for e in case.events]
        steps = []

        time.sleep(delay)
        records_root = sha("".join(sha(canon(r)) for r in recs))
        steps.append(self._step(1, "load_and_hash", {"records": len(recs)}, {"records_root": records_root},
                                f"Loaded {len(recs):,} records and hashed each one (combined hash {records_root[:12]}...)."))
        time.sleep(delay)
        by_src = {s: sum(e.source == s for e in case.events) for s in ("windows", "linux", "aws")}
        steps.append(self._step(2, "normalise", by_src, by_src, f"All records already use one event format: {by_src}."))
        time.sleep(delay)
        case.findings = B.correlate(case.events)
        steps.append(self._step(3, "correlate", {"records": len(recs)}, [dump(f) for f in case.findings],
                                f"Linked suspicious events by user, IP and credential into {len(case.findings)} findings."))
        time.sleep(delay)
        case.findings = B.timeline(case.findings)
        steps.append(self._step(4, "timeline_mitre", [f.id for f in case.findings], [f.technique_id for f in case.findings],
                                "Ordered findings in time and attached MITRE ATT&CK technique IDs."))
        time.sleep(delay)
        ids = sorted({f.technique_id for f in case.findings})
        case.legal = B.map_techniques(ids)
        steps.append(self._step(5, "map_legal", ids, [dump(m) for m in case.legal],
                                f"Suggested {len(case.legal)} legal sections for techniques {ids}. Officer confirms."))
        time.sleep(delay)
        text, conf = self._conclusion(case)
        s6 = self._step(6, "conclude", [f.id for f in case.findings], text, text)
        c = self.ledger.append("conclusion", "agent", {"text": text, "confidence": conf,
                                                      "finding_ids": [f.id for f in case.findings]})
        s6.record_ids.append(str(c.seq))
        steps.append(s6)
        time.sleep(delay)
        case.steps = steps
        pdf = B.s63_draft_pdf(case, self.ledger)
        steps.append(self._step(7, "draft_documents", {"case": case.id}, {"s63_draft_sha256": sha(pdf)},
                                "Drafted the Section 63 certificate (unsigned). The report is made after officer approval."))
        case.steps = steps
        return case

    def explain(self, case) -> list[dict]:
        evs = case.events
        by_id = {e.id: e for e in evs}
        linked = [by_id[i] for f in case.findings for i in f.event_ids if i in by_id]
        if not linked:
            return []
        out = []
        user = max({e.user for e in linked}, key=lambda u: sum(e.user == u for e in linked))
        mine = sorted((e for e in linked if e.user == user), key=lambda e: iso(e.ts_utc))
        ips = sorted({e.ip for e in mine if is_external(e.ip)}) or sorted({e.ip for e in mine})
        pivot = ips[0]
        first = {}
        for e in mine:
            if e.ip == pivot:
                first.setdefault(e.source, e)
        parts = ", ".join(f"{s} ({iso(e.ts_utc)[11:16]})" for s, e in sorted(first.items(), key=lambda kv: iso(kv[1].ts_utc)))
        out.append({"reason": f"Same user {user} and IP {pivot} appear on {len(first)} source(s): {parts}.",
                    "record_ids": [e.id for e in first.values()],
                    "limitation": "Same user and IP shows the account was used from there. It does not show who was at the keyboard."})
        base = [e for e in evs if e.user == user and e.ip != pivot]
        base_ips = sorted({e.ip for e in base})
        days = len({iso(e.ts_utc)[:10] for e in base})
        out.append({"reason": f"Earlier activity of {user} in these records ({len(base)} events over {days} day(s)) used "
                              f"{', '.join(base_ips) or 'no other IP'}; {pivot} appears only in the linked events.",
                    "record_ids": [e.id for e in base[:3]],
                    "limitation": "The baseline only covers the evidence supplied. Older history was not available."})
        keyed = {}
        for e in mine:
            for k in _KEY_RE.findall(e.action):
                keyed.setdefault(k, []).append(e)
        for k, lst in keyed.items():
            lin = [e for e in lst if e.source == "linux"]
            aws = [e for e in lst if e.source == "aws" and e.action.startswith("s3:GetObject")]
            if lin and aws:
                d = (datetime.fromisoformat(iso(aws[0].ts_utc).replace("Z", "+00:00"))
                     - datetime.fromisoformat(iso(lin[-1].ts_utc).replace("Z", "+00:00"))).total_seconds() / 60
                out.append({"reason": f"Access key {k} was read on {lin[-1].host} at {iso(lin[-1].ts_utc)[11:16]} and the first "
                                      f"S3 download with the same key came about {round(d)} minutes later.",
                            "record_ids": [lin[-1].id, aws[0].id],
                            "limitation": "Matching key IDs shows the same key was used. How it was obtained is not established; "
                                          "no phone or email logs, phishing source not confirmed."})
        return out

    def approve(self, case, officer):
        self.ledger.append("approval", officer, {"case": case.id, "officer": officer, "approved": True})
        case.approved = True
        return case

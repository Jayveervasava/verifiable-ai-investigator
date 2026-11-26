"""Ledger: SQLite append-only hash chain with HMAC, Merkle tree and completeness."""
from __future__ import annotations

import hmac as _hmac
import json
import os
import sqlite3
import threading
import warnings
from datetime import datetime, timezone

from ._models import LedgerEntry, make_verify_result
from .completeness import check_completeness, normalize_plan, normalize_step, plan_digest
from .hashing import (GENESIS_HASH, canonical_json, compute_entry_hash, compute_head_hmac,
                      compute_hmac, sha256_hex)
from .merkle import EMPTY_ROOT, MerkleTree

KINDS = ("evidence", "agent_step", "conclusion", "approval", "report")
DEV_KEY = b"vai-dev-key-NOT-FOR-REAL-CASES"
_COLS = "seq, ts, kind, actor, payload, payload_hash, prev_hash, hash, hmac"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries(
  seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL,
  payload TEXT NOT NULL, payload_hash TEXT NOT NULL, prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL, hmac TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries
  BEGIN SELECT RAISE(ABORT, 'ledger is append-only: UPDATE not allowed'); END;
CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries
  BEGIN SELECT RAISE(ABORT, 'ledger is append-only: DELETE not allowed'); END;
"""


class LedgerError(Exception):
    pass


class LedgerTamperedError(LedgerError):
    """Raised when the ledger is found damaged while appending / proving."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _resolve_key(key) -> bytes:
    if key is None:
        key = os.environ.get("LEDGER_HMAC_KEY")
    if not key:
        warnings.warn("LEDGER_HMAC_KEY is not set: using an INSECURE development key. "
                      "Set LEDGER_HMAC_KEY before using this for a real case.",
                      RuntimeWarning, stacklevel=3)
        return DEV_KEY
    return key.encode("utf-8") if isinstance(key, str) else bytes(key)


class Ledger:
    """Append-only, hash-chained, tamper-evident ledger.

    Ledger(db) - `db` is a SQLite file path (or ":memory:").
    """

    def __init__(self, db, hmac_key=None, fast: bool = False):
        self.db = str(db)
        self._key = _resolve_key(hmac_key)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=%s" % ("NORMAL" if fast else "FULL"))
        self._conn.executescript(_SCHEMA)
        self._tree = None
        self._tree_key = None

    # ---- housekeeping ----------------------------------------------------
    def close(self):
        with self._lock:
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @staticmethod
    def _to_entry(row) -> LedgerEntry:
        seq, ts, kind, actor, _payload, ph, pv, h, _mac = row
        return LedgerEntry(seq=seq, ts=ts, kind=kind, actor=actor,
                           payload_hash=ph, prev_hash=pv, hash=h)

    def _read_head(self):
        r = self._conn.execute("SELECT value FROM meta WHERE key='head'").fetchone()
        return json.loads(r[0]) if r else None

    def _head_is_authentic(self, head) -> bool:
        try:
            return _hmac.compare_digest(
                compute_head_hmac(self._key, int(head["seq"]), head["hash"]), head["hmac"])
        except (KeyError, TypeError, ValueError):
            return False

    # ---- append ----------------------------------------------------------
    def append(self, kind: str, actor: str, payload, ts: str | None = None) -> LedgerEntry:
        return self.append_many([(kind, actor, payload, ts)])[0]

    def append_many(self, items) -> list:
        """Append many (kind, actor, payload[, ts]) in ONE transaction (fast)."""
        prepared = []
        for it in items:
            kind, actor, payload = it[0], it[1], it[2]
            ts = it[3] if len(it) > 3 else None
            if kind not in KINDS:
                raise ValueError(f"kind must be one of {KINDS}, got {kind!r}")
            if not isinstance(actor, str) or not actor:
                raise ValueError("actor must be a non-empty string")
            prepared.append((kind, actor, canonical_json(payload), ts))
        if not prepared:
            return []
        with self._lock:
            c = self._conn
            c.execute("BEGIN IMMEDIATE")
            try:
                last = c.execute("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
                head = self._read_head()
                if last is None and head is None:
                    pass
                elif (last is None or head is None or not self._head_is_authentic(head)
                      or head["seq"] != last[0] or head["hash"] != last[1]):
                    raise LedgerTamperedError(
                        "ledger head does not match stored entries - refusing to append. "
                        "Run verify() to see where it is broken.")
                seq, prev = (last[0], last[1]) if last else (0, GENESIS_HASH)
                rows = []
                for kind, actor, text, ts in prepared:
                    seq += 1
                    ts = ts or utc_now()
                    ph = sha256_hex(text)
                    h = compute_entry_hash(prev, ph, seq, ts, kind, actor)
                    rows.append((seq, ts, kind, actor, text, ph, prev, h, compute_hmac(self._key, h)))
                    prev = h
                c.executemany(f"INSERT INTO entries({_COLS}) VALUES(?,?,?,?,?,?,?,?,?)", rows)
                c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('head', ?)",
                          (json.dumps({"seq": seq, "hash": prev,
                                       "hmac": compute_head_hmac(self._key, seq, prev)}),))
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise
            self._tree = None
        return [self._to_entry(r) for r in rows]

    # ---- read ------------------------------------------------------------
    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def entries(self) -> list:
        with self._lock:
            return [self._to_entry(r) for r in
                    self._conn.execute(f"SELECT {_COLS} FROM entries ORDER BY seq")]

    def get(self, seq: int):
        with self._lock:
            r = self._conn.execute(f"SELECT {_COLS} FROM entries WHERE seq=?", (seq,)).fetchone()
        return self._to_entry(r) if r else None

    def records(self) -> list:
        """Entries WITH payload (dicts) - what reports / completeness use."""
        with self._lock:
            return [self._record(r) for r in
                    self._conn.execute(f"SELECT {_COLS} FROM entries ORDER BY seq")]

    @staticmethod
    def _record(r) -> dict:
        seq, ts, kind, actor, payload, ph, pv, h, mac = r
        return {"seq": seq, "ts": ts, "kind": kind, "actor": actor,
                "payload": json.loads(payload), "payload_hash": ph,
                "prev_hash": pv, "hash": h, "hmac": mac}

    def anchor(self) -> dict:
        """Small summary to store OUTSIDE the database (printed in the report,
        emailed, etc). verify(expected_head=...) can check against it later."""
        with self._lock:
            last = self._conn.execute("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            return {"seq": last[0] if last else 0, "hash": last[1] if last else GENESIS_HASH,
                    "merkle_root": self.merkle_root(), "ts": utc_now()}

    # ---- verify ----------------------------------------------------------
    def verify(self, expected_head: dict | None = None):
        return self.verify_with_reason(expected_head)[0]

    def verify_with_reason(self, expected_head: dict | None = None):
        """Return (VerifyResult, reason). broken_at = first broken seq."""
        with self._lock:
            def fail(n, seq, why):
                return make_verify_result(False, n, seq), why

            prev, exp, n = GENESIS_HASH, 1, 0
            cur = self._conn.execute(f"SELECT {_COLS} FROM entries ORDER BY seq")
            for seq, ts, kind, actor, payload, ph, pv, h, mac in cur:
                if seq != exp:
                    return fail(n, exp, f"entry {exp} is missing or numbering is wrong "
                                f"(found {seq}): an entry was deleted or inserted")
                if sha256_hex(payload) != ph:
                    return fail(n, seq, "payload was changed (payload_hash does not match)")
                if pv != prev:
                    return fail(n, seq, "chain link broken (prev_hash does not match previous entry)")
                if compute_entry_hash(pv, ph, seq, ts, kind, actor) != h:
                    return fail(n, seq, "entry fields were changed (hash does not match)")
                if not _hmac.compare_digest(compute_hmac(self._key, h), mac):
                    return fail(n, seq, "HMAC invalid: entry was not written with the ledger key "
                                "(forged, or chain was rebuilt by someone without the key)")
                prev, exp, n = h, exp + 1, n + 1
            last_seq = exp - 1
            head = self._read_head()
            if head is None:
                if last_seq:
                    return fail(n, last_seq, "ledger head record is missing")
            else:
                if not self._head_is_authentic(head):
                    return fail(n, max(last_seq, 1), "ledger head record was forged (HMAC invalid)")
                if head["seq"] > last_seq:
                    return fail(n, last_seq + 1, f"{head['seq'] - last_seq} entr"
                                f"{'y' if head['seq'] - last_seq == 1 else 'ies'} missing from the "
                                "end (ledger truncated)")
                if head["seq"] < last_seq:
                    return fail(n, head["seq"] + 1, "entries exist beyond the recorded head "
                                "(added outside the ledger)")
                if head["hash"] != prev:
                    return fail(n, last_seq, "last entry does not match the recorded head")
            if expected_head is not None:
                eseq = int(expected_head["seq"])
                if eseq > last_seq:
                    return fail(n, last_seq + 1, "ledger is shorter than the external anchor "
                                "(entries removed)")
                if eseq >= 1:
                    r = self._conn.execute("SELECT hash FROM entries WHERE seq=?", (eseq,)).fetchone()
                    if r[0] != expected_head["hash"]:
                        return fail(n, eseq, "entry differs from the external anchor")
            return make_verify_result(True, n, None), "ledger is intact"

    # ---- Merkle ----------------------------------------------------------
    def _get_tree(self) -> MerkleTree:
        with self._lock:
            last = self._conn.execute("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            key = tuple(last) if last else None
            if self._tree is None or self._tree_key != key:
                hashes = [r[0] for r in self._conn.execute("SELECT hash FROM entries ORDER BY seq")]
                if last and len(hashes) != last[0]:
                    raise LedgerTamperedError("entry numbering has gaps - run verify()")
                self._tree, self._tree_key = MerkleTree(hashes), key
            return self._tree

    def merkle_root(self) -> str:
        return self._get_tree().root if self.count() else EMPTY_ROOT

    def merkle_proof(self, seq: int) -> dict:
        """Self-contained proof that entry `seq` is inside the ledger with the
        given root. Check with vai.ledger.verify_proof(proof, trusted_root)."""
        with self._lock:
            tree = self._get_tree()
            if not 1 <= seq <= tree.size:
                raise KeyError(f"no entry with seq={seq}")
            r = self._conn.execute(f"SELECT {_COLS} FROM entries WHERE seq=?", (seq,)).fetchone()
            _s, ts, kind, actor, _p, ph, pv, h, _m = r
            return {"version": 1, "tree_size": tree.size, "root": tree.root,
                    "entry": {"seq": seq, "ts": ts, "kind": kind, "actor": actor,
                              "payload_hash": ph, "prev_hash": pv, "hash": h},
                    "path": tree.path(seq - 1)}

    # ---- agent protocol helpers (use these so completeness works) -------
    def commit_plan(self, plan, actor: str) -> LedgerEntry:
        """Call BEFORE running any step. `plan` = list of {n, tool, input_hash?}."""
        steps = normalize_plan(plan)
        return self.append("agent_step", actor, {"phase": "plan", "plan_hash": plan_digest(steps),
                                                 "steps": steps})

    def step_started(self, n: int, tool: str, input_hash: str, actor: str) -> LedgerEntry:
        return self.append("agent_step", actor, {"phase": "before", "n": int(n), "tool": tool,
                                                 "input_hash": input_hash})

    def step_finished(self, n: int, tool: str, output_hash: str, actor: str,
                      record_ids=None, reasoning: str = "") -> LedgerEntry:
        return self.append("agent_step", actor, {
            "phase": "after", "n": int(n), "tool": tool, "output_hash": output_hash,
            "record_ids": list(record_ids or []), "reasoning": reasoning})

    # ---- completeness ----------------------------------------------------
    def completeness_report(self, plan, entries=None) -> list:
        """Detailed list of problems (dicts). Empty list = complete."""
        return self._completeness(plan, entries)[0]

    def verify_completeness(self, plan, entries=None):
        """Did the agent do exactly the committed plan?  missing_steps holds
        readable problems. `entries` = list of LedgerEntry (default: all)."""
        problems, checked = self._completeness(plan, entries)
        texts = [f"[{p['code']}] seq={p['seq']} {p['detail']}" if p["seq"] is not None
                 else f"[{p['code']}] {p['detail']}" for p in problems]
        first = next((p["seq"] for p in problems if p["seq"] is not None), None)
        return make_verify_result(not problems, checked, first, texts,
                                  [p["step"] for p in problems if isinstance(p["step"], int)])

    def _completeness(self, plan, entries):
        with self._lock:
            problems, records = [], []
            if entries is None:
                records = self.records()
            else:
                for e in entries:
                    if isinstance(e, dict) and "payload" in e:
                        records.append(e)
                        continue
                    seq = e["seq"] if isinstance(e, dict) else e.seq
                    eh = e["hash"] if isinstance(e, dict) else e.hash
                    eph = e["payload_hash"] if isinstance(e, dict) else e.payload_hash
                    r = self._conn.execute(f"SELECT {_COLS} FROM entries WHERE seq=?", (seq,)).fetchone()
                    if r is None or r[7] != eh or sha256_hex(r[4]) != eph or r[5] != eph:
                        problems.append({"code": "ENTRY_MISMATCH", "seq": seq, "step": None,
                                         "detail": "entry does not match what is stored in the ledger"})
                        continue
                    records.append(self._record(r))
            found, checked = check_completeness(plan, records)
            allp = problems + found
            allp.sort(key=lambda p: (p["seq"] is None, p["seq"] or 0))
            return allp, checked

    def full_audit(self, plan, expected_head: dict | None = None) -> dict:
        """Chain check + completeness check + Merkle root, in one call."""
        chain, why = self.verify_with_reason(expected_head)
        comp = self.verify_completeness(plan)
        return {"ok": bool(chain.ok and comp.ok), "chain": chain, "chain_reason": why,
                "completeness": comp, "merkle_root": self.merkle_root(),
                "entries": self.count()}

    # ---- export ----------------------------------------------------------
    def export_package(self, path, case_id: str | None = None, overwrite: bool = False):
        from .export import export_package
        return export_package(self, path, case_id=case_id, overwrite=overwrite)

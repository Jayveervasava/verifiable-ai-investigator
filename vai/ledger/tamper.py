"""Tamper demo: simulate an attacker who has the database FILE (but not the
HMAC key), then show that verify() catches it.

WARNING: tamper_demo() changes the database it is given. Always run it on a
COPY (use copy_db()). The web UI must never point it at the real case ledger.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3

from .core import Ledger
from .hashing import GENESIS_HASH, canonical_json, compute_entry_hash, sha256_hex

MODES = ("edit", "delete", "insert", "reorder")
_FIELDS = ("seq", "ts", "kind", "actor", "payload", "payload_hash", "prev_hash", "hash", "hmac")


def copy_db(db, dest=None) -> str:
    """Safe copy of a ledger DB (uses SQLite backup, so WAL data is included)."""
    db = db.db if isinstance(db, Ledger) else str(db)
    dest = str(dest) if dest else db + ".tamper_copy"
    if os.path.exists(dest):
        raise FileExistsError(f"{dest} already exists; choose another name or delete it yourself")
    src, dst = sqlite3.connect(db), sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()
    return dest


def _rechain(rows, start):
    """Attacker re-computes plain SHA-256 links from `start` (cannot make HMACs)."""
    prev = rows[start - 1]["hash"] if start > 0 else GENESIS_HASH
    for r in rows[start:]:
        r["payload_hash"] = sha256_hex(r["payload"])
        r["prev_hash"] = prev
        r["hash"] = compute_entry_hash(prev, r["payload_hash"], r["seq"], r["ts"], r["kind"], r["actor"])
        prev = r["hash"]


def tamper_demo(db, seq: int, mode: str = "edit", *, recompute_chain: bool = False, key=None) -> dict:
    """Attack entry `seq` and report whether verify() detects it.

    mode: edit | delete | insert | reorder(swap seq and seq+1)
    recompute_chain=True: attacker also rebuilds all SHA-256 links after the
      change (the strongest attack without the key). Only the HMAC then catches it.
    `db`: path to a COPY of the ledger (or a Ledger object; then its key is used).
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    if isinstance(db, Ledger):
        ledger, path = db, db.db
    else:
        ledger, path = None, str(db)
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        # attacker with file access can drop the append-only triggers
        conn.execute("DROP TRIGGER IF EXISTS entries_no_update")
        conn.execute("DROP TRIGGER IF EXISTS entries_no_delete")
        rows = [dict(r) for r in conn.execute("SELECT * FROM entries ORDER BY seq")]
        n = len(rows)
        i = seq - 1
        if mode in ("edit", "delete", "reorder") and not 1 <= seq <= n:
            raise ValueError(f"seq must be 1..{n}")
        if mode == "insert" and not 1 <= seq <= n + 1:
            raise ValueError(f"seq must be 1..{n + 1}")
        if mode == "reorder" and seq >= n:
            raise ValueError(f"reorder swaps seq and seq+1, so seq must be 1..{n - 1}")

        if mode == "edit":
            p = json.loads(rows[i]["payload"])
            p = {**p, "tampered_by_demo": True} if isinstance(p, dict) else {"value": p, "tampered_by_demo": True}
            rows[i]["payload"] = canonical_json(p)
            if recompute_chain:
                _rechain(rows, i)
            what = f"edited the payload of entry {seq}"
        elif mode == "delete":
            del rows[i]
            if recompute_chain:
                for j in range(i, len(rows)):
                    rows[j]["seq"] = j + 1
                _rechain(rows, i)
            what = f"deleted entry {seq}"
        elif mode == "insert":
            prev = rows[i - 1]["hash"] if i > 0 else GENESIS_HASH
            text = canonical_json({"phase": "after", "n": 999, "tool": "forged_tool",
                                   "output_hash": "f" * 64})
            ph = sha256_hex(text)
            ts = rows[i - 1]["ts"] if i > 0 else rows[0]["ts"]
            fake = {"seq": seq, "ts": ts, "kind": "agent_step", "actor": "attacker", "payload": text,
                    "payload_hash": ph, "prev_hash": prev,
                    "hash": compute_entry_hash(prev, ph, seq, ts, "agent_step", "attacker"),
                    "hmac": "0" * 64}
            for r in rows[i:]:
                r["seq"] += 1
            rows.insert(i, fake)
            if recompute_chain:
                _rechain(rows, i + 1)
            what = f"inserted a fake step at position {seq}"
        else:  # reorder
            a, b = rows[i], rows[i + 1]
            for f in _FIELDS[1:]:
                a[f], b[f] = b[f], a[f]
            if recompute_chain:
                _rechain(rows, i)
            what = f"swapped entries {seq} and {seq + 1}"

        conn.execute("BEGIN")
        conn.execute("DELETE FROM entries")
        conn.executemany(
            "INSERT INTO entries(%s) VALUES(%s)" % (", ".join(_FIELDS), ",".join("?" * len(_FIELDS))),
            [tuple(r[f] for f in _FIELDS) for r in rows])
        conn.execute("COMMIT")
    finally:
        conn.close()

    checker = ledger if ledger is not None else Ledger(path, hmac_key=key)
    result, reason = checker.verify_with_reason()
    if ledger is None:
        checker.close()
    return {"mode": mode, "seq": seq, "recompute_chain": recompute_chain, "attacker_did": what,
            "detected": not result.ok, "broken_at": result.broken_at, "reason": reason,
            "verify": result.model_dump() if hasattr(result, "model_dump") else vars(result)}

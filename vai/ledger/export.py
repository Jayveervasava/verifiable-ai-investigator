"""export_package(): one zip anyone can verify later, without our software."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import zipfile
from pathlib import Path

from .hashing import HASH_ALGORITHM
from .merkle import EMPTY_ROOT

README = """VAI LEDGER EXPORT / Ledger export package
==========================================
Files:
  manifest.json     summary: entry count, last entry hash, Merkle root, verify result at export
  entries.jsonl     every ledger entry (one JSON per line, payload kept as exact text)
  ledger.sqlite     copy of the ledger database
  verify_ledger.py  standalone checker (only Python needed)

How to verify (Hinglish):
  1. Zip ko kisi folder me extract karo.
  2. Command chalao:   python verify_ledger.py
  3. "RESULT: PASS" aaye to hash chain + Merkle root sahi hain.
  4. manifest.json ke merkle_root ko report/trusted copy se match karo.
Optional: LEDGER_HMAC_KEY set karoge to har entry ka HMAC bhi check hoga.

This proves the records are unchanged since they were written (verifiable).
It does not by itself decide admissibility - the court / officer decides.
"""


def export_package(ledger, path, case_id=None, overwrite=False) -> Path:
    from .core import utc_now
    path = Path(path)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists (pass overwrite=True to replace it)")
    chain, why = ledger.verify_with_reason()
    recs = ledger.records()
    head = {"seq": recs[-1]["seq"], "hash": recs[-1]["hash"]} if recs else {"seq": 0, "hash": "0" * 64}
    manifest = {
        "format_version": 1, "created_utc": utc_now(), "case_id": case_id,
        "algorithm": {"hash": HASH_ALGORITHM, "chain": "sha256(prev|payload_hash|seq|ts|kind|actor)",
                      "merkle": "leaf=sha256(00||h), node=sha256(01||l||r), odd node carried up",
                      "hmac": "HMAC-SHA256(key, hash) - key NOT included"},
        "entry_count": len(recs), "head": head,
        "merkle_root": ledger.merkle_root() if recs else EMPTY_ROOT,
        "chain_verified_at_export": bool(chain.ok), "verify_reason": why,
    }
    with tempfile.TemporaryDirectory() as tmp:
        dbcopy = os.path.join(tmp, "ledger.sqlite")
        src, dst = sqlite3.connect(ledger.db), sqlite3.connect(dbcopy)
        try:
            src.backup(dst)
        finally:
            src.close(); dst.close()
        lines = "".join(json.dumps({k: r[k] for k in ("seq", "ts", "kind", "actor")}
                                   | {"payload": _payload_text(ledger, r["seq"]),
                                      "payload_hash": r["payload_hash"], "prev_hash": r["prev_hash"],
                                      "hash": r["hash"], "hmac": r["hmac"]}, ensure_ascii=False) + "\n"
                        for r in recs)
        part = str(path) + ".partial"
        with zipfile.ZipFile(part, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
            z.writestr("entries.jsonl", lines)
            z.writestr("README.txt", README)
            z.write(os.path.join(os.path.dirname(__file__), "standalone_verify.py"), "verify_ledger.py")
            z.write(dbcopy, "ledger.sqlite")
        os.replace(part, path)
    return path


def _payload_text(ledger, seq):
    return ledger._conn.execute("SELECT payload FROM entries WHERE seq=?", (seq,)).fetchone()[0]

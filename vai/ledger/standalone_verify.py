#!/usr/bin/env python3
"""Standalone ledger verifier - needs ONLY Python 3.8+ (no other packages).

Usage:  python verify_ledger.py [folder]      (folder = unzipped export, default: here)
Optional: set LEDGER_HMAC_KEY to also check the HMAC of every entry.
Exit code 0 = PASS, 1 = FAIL.   (Intentionally independent of the main code.)
"""
import hashlib
import hmac
import json
import os
import sys

GENESIS = "0" * 64


def h256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def entry_hash(prev, ph, seq, ts, kind, actor):
    return h256("|".join([prev, ph, str(seq), ts, kind, actor]))


def merkle_root(hashes):
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest() for h in hashes]
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def verify(folder):
    problems = []
    with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    key = os.environ.get("LEDGER_HMAC_KEY")
    prev, hashes = GENESIS, []
    with open(os.path.join(folder, "entries.jsonl"), encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            seq = len(hashes) + 1
            if e["seq"] != seq:
                problems.append("entry %d missing/misnumbered (found %s)" % (seq, e["seq"])); break
            if h256(e["payload"]) != e["payload_hash"]:
                problems.append("entry %d: payload changed" % seq); break
            if e["prev_hash"] != prev:
                problems.append("entry %d: chain link broken" % seq); break
            if entry_hash(prev, e["payload_hash"], seq, e["ts"], e["kind"], e["actor"]) != e["hash"]:
                problems.append("entry %d: hash mismatch" % seq); break
            if key and not hmac.compare_digest(
                    hmac.new(key.encode(), e["hash"].encode(), hashlib.sha256).hexdigest(), e["hmac"]):
                problems.append("entry %d: HMAC invalid" % seq); break
            prev = e["hash"]
            hashes.append(prev)
    if not problems:
        if len(hashes) != manifest["entry_count"]:
            problems.append("entry count %d differs from manifest %d" % (len(hashes), manifest["entry_count"]))
        elif prev != manifest["head"]["hash"]:
            problems.append("last entry hash differs from manifest head")
        elif merkle_root(hashes) != manifest["merkle_root"]:
            problems.append("Merkle root differs from manifest")
    return problems, len(hashes), bool(key)


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    probs, n, with_hmac = verify(folder)
    print("Entries checked:", n, "| HMAC checked:", "yes" if with_hmac else "no (set LEDGER_HMAC_KEY)")
    if probs:
        print("RESULT: FAIL -", "; ".join(probs))
        print("Matlab: ledger ke saath chhed-chhad hui hai ya file adhuri hai.")
        sys.exit(1)
    print("RESULT: PASS - ledger intact (verifiable). Hash chain + Merkle root sahi hain.")
    print("Note: manifest.json ka merkle_root ek trusted jagah (report) se bhi match karo.")

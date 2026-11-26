"""Demo on synthetic case FIR-1427/2027. Run:  python -m vai.ledger.demo [--out results/ledger]
Writes config, tamper results, completeness results, a Merkle proof and an export zip."""
import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path

from . import Ledger, copy_db, tamper_demo, verify_proof
from .hashing import GENESIS_HASH, HASH_ALGORITHM

KEY = "demo-key-not-secret"


def build_case(db):
    led = Ledger(db, hmac_key=KEY)
    for i, f in enumerate(["windows_security.evtx", "linux_auth.log", "aws_cloudtrail.json"], 1):
        led.append("evidence", "evidence:ingest", {"file": f, "sha256": f"{i:064x}"})
    plan = [{"n": 1, "tool": "ingest", "input_hash": ""}, {"n": 2, "tool": "correlate", "input_hash": ""},
            {"n": 3, "tool": "timeline", "input_hash": ""}, {"n": 4, "tool": "map_legal", "input_hash": ""}]
    led.commit_plan(plan, "agent:rule-based")
    for s in plan:
        led.step_started(s["n"], s["tool"], f"in{s['n']:062x}", "agent:rule-based")
        led.step_finished(s["n"], s["tool"], f"out{s['n']:060x}", "agent:rule-based", [s["n"]], "synthetic demo step")
    led.append("conclusion", "agent:rule-based", {"text": "T1078 -> T1021 -> T1530 chain", "record_ids": [5, 7, 9],
                                                  "limitations": "synthetic data; officer confirms"})
    led.append("approval", "officer:SI R. Patel (fictional)", {"approved": True})
    return led, plan


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="results/ledger")
    out = Path(ap.parse_args().out); out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        led, plan = build_case(os.path.join(tmp, "case.db"))
        (out / "config.json").write_text(json.dumps({
            "hash": HASH_ALGORITHM, "genesis": GENESIS_HASH, "entry_hash": "sha256(prev|payload_hash|seq|ts|kind|actor)",
            "hmac_env": "LEDGER_HMAC_KEY", "merkle": "domain-separated, odd node carried up",
            "demo_key_is_public": True}, indent=2))
        tam = []
        n = led.count()
        for mode, positions in (("edit", [1, n // 2, n]), ("delete", [1, n // 2, n]),
                                ("insert", [1, n // 2, n + 1]), ("reorder", [1, n // 2, n - 1])):
            for rc in (False, True):
                for seq in positions:
                    cp = copy_db(led, os.path.join(tmp, f"t_{mode}_{seq}_{int(rc)}.db"))
                    tam.append(tamper_demo(cp, seq, mode, recompute_chain=rc, key=KEY))
        (out / "tamper_demo_results.json").write_text(json.dumps(tam, indent=2))
        comp = {"honest": led.verify_completeness(plan).model_dump(),
                "full_audit_ok": led.full_audit(plan)["ok"]}
        bad = Ledger(os.path.join(tmp, "bad.db"), hmac_key=KEY)
        bad.commit_plan(plan, "agent")
        bad.step_started(1, "ingest", "i", "agent"); bad.step_finished(1, "ingest", "o", "agent")
        bad.step_started(2, "correlate", "i", "agent")                       # never finished
        bad.step_started(77, "wipe_logs", "i", "agent"); bad.step_finished(77, "wipe_logs", "o", "agent")
        comp["agent_that_hid_steps"] = bad.verify_completeness(plan).model_dump()
        (out / "completeness_demo.json").write_text(json.dumps(comp, indent=2))
        proof = led.merkle_proof(7)
        (out / "merkle_proof_example.json").write_text(json.dumps(
            {"proof": proof, "valid_with_trusted_root": verify_proof(proof, led.merkle_root())}, indent=2))
        led.export_package(out / "ledger_export_example.zip", case_id="FIR-1427/2027 (synthetic)", overwrite=True)
        det = sum(t["detected"] for t in tam)
        print(f"Tamper attacks: {det}/{len(tam)} detected | completeness of honest run: "
              f"{comp['honest']['ok']} | cheating agent flagged: {not comp['agent_that_hid_steps']['ok']}")
        print("Saved to", out.resolve())


if __name__ == "__main__":
    main()

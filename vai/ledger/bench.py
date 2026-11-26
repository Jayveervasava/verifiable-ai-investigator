"""Timing benchmark. Run:  python -m vai.ledger.bench [--out results/ledger] [--max 100000]"""
import argparse
import json
import os
import platform
import tempfile
import time
from pathlib import Path

from . import Ledger, verify_proof


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/ledger"); ap.add_argument("--max", type=int, default=100_000)
    a = ap.parse_args(); out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    rows = []
    for size in sorted({1_000, 10_000, 50_000, a.max}):
        if size > a.max:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            led = Ledger(os.path.join(tmp, "b.db"), hmac_key="bench", fast=True)
            items = [("agent_step", "agent", {"phase": "after", "n": i, "output_hash": "%064x" % i}) for i in range(size)]
            t = time.perf_counter(); led.append_many(items); ta = time.perf_counter() - t
            t = time.perf_counter(); ok = led.verify().ok; tv = time.perf_counter() - t
            t = time.perf_counter(); root = led.merkle_root(); tr = time.perf_counter() - t
            t = time.perf_counter(); p = led.merkle_proof(size // 2); tp = time.perf_counter() - t
            rows.append({"entries": size, "append_s": round(ta, 3), "verify_s": round(tv, 3),
                         "merkle_root_s": round(tr, 3), "proof_s": round(tp, 4),
                         "verify_ok": ok, "proof_ok": verify_proof(p, root)})
            led.close()
    meta = {"python": platform.python_version(), "machine": platform.platform(), "rows": rows}
    (out / "timing.json").write_text(json.dumps(meta, indent=2))
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6, 4)); xs = [r["entries"] for r in rows]
        for k, lab in (("append_s", "append"), ("verify_s", "verify"), ("merkle_root_s", "merkle root")):
            ax.plot(xs, [r[k] for r in rows], marker="o", label=lab)
        ax.set_xlabel("ledger entries"); ax.set_ylabel("seconds"); ax.set_title("Ledger timing"); ax.legend()
        fig.tight_layout(); fig.savefig(out / "timing.png", dpi=150)
    except ImportError:
        pass
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()

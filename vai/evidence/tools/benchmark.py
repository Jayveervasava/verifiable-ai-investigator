"""Speed benchmark: ingest + correlate on N synthetic records (default 100,000).

    python -m vai.evidence.tools.benchmark                 # writes results/evidence/speed_100k.json and speed_note.txt
    python -m vai.evidence.tools.benchmark --records 50000
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path

from vai.evidence import correlate, ingest
from .generate_case1 import generate_case


def run(records: int, repeat: int = 3) -> dict:
    d = Path(tempfile.mkdtemp(prefix="vai_bench_"))
    generate_case(d, records)
    size_mb = sum(p.stat().st_size for p in d.iterdir()) / 1e6
    runs = []
    for _ in range(repeat):
        t0 = time.perf_counter(); ev = ingest(d)
        t1 = time.perf_counter(); fs = correlate(ev)
        t2 = time.perf_counter()
        runs.append({"ingest_s": round(t1 - t0, 3), "correlate_s": round(t2 - t1, 3), "total_s": round(t2 - t0, 3)})
    best = min(runs, key=lambda r: r["total_s"])
    return {"records": len(ev), "input_size_mb": round(size_mb, 1), "findings": len(fs), "runs": runs, "best": best,
            "records_per_second": int(len(ev) / best["total_s"]),
            "machine": {"python": sys.version.split()[0], "platform": platform.platform(), "cpus": os.cpu_count()}}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--records", type=int, default=100000)
    ap.add_argument("--out", default="results/evidence")
    a = ap.parse_args()
    res = run(a.records)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    tag = f"{a.records // 1000}k"
    (out / f"speed_{tag}.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    note = (f"Speed note: {res['records']:,} records ({res['input_size_mb']} MB of logs) -> ingest {res['best']['ingest_s']} s + "
            f"correlate {res['best']['correlate_s']} s = {res['best']['total_s']} s (best of {len(res['runs'])}), "
            f"about {res['records_per_second']:,} records/second, {res['findings']} findings.\n"
            f"Machine: Python {res['machine']['python']}, {res['machine']['cpus']} CPUs, {res['machine']['platform']}.\n"
            "Single process, pure Python, no pre-built index. Numbers differ on other computers.\n")
    (out / f"speed_note_{tag}.txt").write_text(note, encoding="utf-8")
    print(note)


if __name__ == "__main__":
    main()

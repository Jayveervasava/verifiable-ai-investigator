"""Generate sample outputs of vai.legal into a results folder.

    python -m vai.legal.cli --out results/legal

Writes: sample_case_report.pdf, sample_s63_draft.pdf, legal_mapping_table.csv,
mitre_to_law_snapshot.json, legal_run_config.json, law_coverage.png.
Uses the synthetic MOCK case, not real data.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import mapping
from ._compat import STATUS_TEXT
from ._mock import build_demo
from .report import case_report_pdf
from .s63 import s63_draft_pdf


def _figure(path: Path) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:  # noqa: BLE001
        return False
    techniques = mapping.load_mapping()["techniques"]
    ids = list(techniques)
    cols = ["IT Act 2000", "BNS 2023"]
    data = [[sum(1 for e in techniques[t]["entries"] if e["act"] == a) for a in cols] for t in ids]
    fig, ax = plt.subplots(figsize=(4.8, 5))
    ax.imshow(data, cmap="Blues", vmin=0, vmax=max(max(r) for r in data))
    ax.set_xticks(range(len(cols)), cols)
    ax.set_yticks(range(len(ids)), [f"{t} {techniques[t]['name']}" for t in ids])
    for i, row in enumerate(data):
        for j, v in enumerate(row):
            ax.text(j, i, v, ha="center", va="center")
    ax.set_title("Suggested law entries per MITRE technique")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="results/legal", help="output folder (default results/legal)")
    out = Path(ap.parse_args(argv).out)
    out.mkdir(parents=True, exist_ok=True)

    fixed = datetime(2027, 1, 15, 12, 0, tzinfo=timezone.utc)  # fixed so outputs are reproducible
    case, ledger, plan = build_demo(approved=False)
    (out / "sample_case_report.pdf").write_bytes(case_report_pdf(case, ledger, plan=plan, generated_at=fixed))
    (out / "sample_s63_draft.pdf").write_bytes(s63_draft_pdf(case, ledger, plan=plan, generated_at=fixed))

    data = mapping.load_mapping()
    with open(out / "legal_mapping_table.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["technique_id", "technique_name", "act", "section", "offence", "reason", "source_url", "status", "doubt"])
        for tid, block in data["techniques"].items():
            for e in block["entries"]:
                w.writerow([tid, block["name"], e["act"], e["section"], e["offence"], e["reason"],
                            e["source_url"], STATUS_TEXT,
                            e.get("doubt") or ""])
    snapshot = {
        "yaml_sha256": mapping.mapping_sha256(), "meta": data["meta"],
        "techniques": len(data["techniques"]),
        "entries": sum(len(b["entries"]) for b in data["techniques"].values()),
        "validation_problems": mapping.validate_mapping(data),
    }
    (out / "mitre_to_law_snapshot.json").write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    fig_ok = _figure(out / "law_coverage.png")
    config = {"generated_fixed_time_utc": fixed.isoformat(), "python": sys.version.split()[0],
              "case": "synthetic mock of Demo case 1 (vai.legal._mock)", "figure_written": fig_ok}
    (out / "legal_run_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(f"Saved results to {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

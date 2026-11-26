"""Run both demo cases and save every result / config / figure to results/evidence/.

    python -m vai.evidence.tools.make_results
Files written (per case): <case>_events.jsonl, <case>_findings.json, <case>_timeline.txt,
<case>_ingest_report.json, <case>_timeline.svg ; plus config.json (all parameters + limitations).
"""
from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path

from vai.evidence import EVIDENCE_LIMITATIONS, correlate, ingest_with_report, timeline, timeline_text
from vai.evidence.common import event_dt
from vai.evidence.rules import RULES

CASES = {"case_fir_1427": "data/sample/case_fir_1427", "case_public": "data/sample/case_public"}
COLORS = {"high": "#c0392b", "medium": "#e67e22", "low": "#7f8c8d"}


def _svg(findings, events, title: str) -> str:
    ts = {e.id: event_dt(e) for e in events}
    story = [f for f in timeline(findings, events, min_confidence="medium")] or timeline(findings, events)
    pts = [(f, min(ts[i] for i in f.event_ids)) for f in story if any(i in ts for i in f.event_ids)]
    if not pts:
        return "<svg xmlns='http://www.w3.org/2000/svg' width='400' height='60'><text x='10' y='30'>no findings</text></svg>"
    t0 = min(t for _, t in pts); t1 = max(t for _, t in pts)
    span = max((t1 - t0).total_seconds(), 1)
    W, rowh, left = 1000, 34, 330
    H = 70 + rowh * len(pts)
    o = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' font-family='sans-serif' font-size='12'>",
         f"<rect width='{W}' height='{H}' fill='white'/><text x='10' y='22' font-size='15' font-weight='bold'>{title}</text>",
         f"<text x='10' y='42' fill='#555'>{t0:%Y-%m-%d %H:%M:%S}Z  to  {t1:%H:%M:%S}Z   (colour = confidence: red high, orange medium, grey low)</text>",
         f"<line x1='{left}' y1='55' x2='{W - 20}' y2='55' stroke='#999'/>"]
    for n, (f, t) in enumerate(pts):
        y = 55 + rowh * (n + 1)
        x = left + (W - 20 - left) * ((t - t0).total_seconds() / span)
        o.append(f"<text x='10' y='{y + 4}'>{f.technique_id}  [{f.confidence}]  {f.title.split(':')[0][:40]}</text>")
        o.append(f"<line x1='{left}' y1='{y}' x2='{W - 20}' y2='{y}' stroke='#eee'/>")
        o.append(f"<circle cx='{x:.1f}' cy='{y}' r='7' fill='{COLORS[f.confidence]}'><title>{f.id} {len(f.event_ids)} events</title></circle>")
    o.append("</svg>")
    return "\n".join(o)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="results/evidence")
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    params = {k: v.default for k, v in inspect.signature(correlate).parameters.items() if v.default is not inspect._empty}
    summary = {}
    for name, path in CASES.items():
        if not Path(path).exists():
            print(f"skip {name}: {path} not found"); continue
        events, report = ingest_with_report(path)
        findings = correlate(events)
        with open(out / f"{name}_events.jsonl", "w", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e.model_dump(mode="json")) + "\n")
        (out / f"{name}_findings.json").write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
        (out / f"{name}_ingest_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        (out / f"{name}_timeline.txt").write_text(timeline_text(findings, events, min_confidence="medium") + "\n", encoding="utf-8")
        (out / f"{name}_timeline.svg").write_text(_svg(findings, events, f"{name}: attack timeline (medium+ findings)"), encoding="utf-8")
        summary[name] = {"events": len(events), "findings": len(findings), "high": sum(f.confidence == "high" for f in findings)}
        print(name, summary[name])
    (out / "config.json").write_text(json.dumps({"correlate_defaults": params, "rules": [r.rid for r in RULES],
                                                  "limitations": EVIDENCE_LIMITATIONS, "summary": summary}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()

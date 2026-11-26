"""Shared test helpers (plain functions, no pytest dependency)."""
import json
import tempfile
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASE1 = ROOT / "data" / "sample" / "case_fir_1427"
PUBLIC = ROOT / "data" / "sample" / "case_public"


@lru_cache(maxsize=None)
def run_case(path: str):
    """ingest + correlate once per folder -> (events, findings, report, by_raw_ref)."""
    from vai.evidence import correlate, ingest_with_report
    events, report = ingest_with_report(path)
    findings = correlate(events)
    return events, findings, report, {e.raw_ref: e for e in events}


@lru_cache(maxsize=None)
def tmp_case1(records: int):
    """Fresh generated case in a temp folder (used when data/ is missing or for size tests)."""
    from vai.evidence.tools.generate_case1 import generate_case
    d = Path(tempfile.mkdtemp(prefix="vai_case_"))
    generate_case(d, records)
    return str(d)


def truth(path: Path):
    name = "_ground_truth.json" if (path / "_ground_truth.json").exists() else "_expected.json"
    return json.loads((path / name).read_text(encoding="utf-8"))

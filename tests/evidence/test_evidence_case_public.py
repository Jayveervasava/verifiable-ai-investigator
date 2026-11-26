"""Demo case 2 (public-data style): the planted techniques must be found, and nothing benign flagged."""

from pathlib import Path
from evidence_helpers import PUBLIC, run_case, truth
import tempfile


def _case():
    if not (PUBLIC / "_expected.json").exists():
        from vai.evidence.tools.build_public_case import build
        d = Path(tempfile.mkdtemp()); build(d); return d
    return PUBLIC


def test_all_expected_techniques_found_on_the_planted_records():
    events, findings, report, by_ref = run_case(str(_case()))
    gt = truth(_case())
    assert report["total_errors"] == 0
    for rec in gt["records"]:
        eid = by_ref[rec["raw_ref"]].id
        for tech in rec["techniques"]:
            assert any(f.technique_id == tech and eid in f.event_ids for f in findings), (tech, rec["raw_ref"])
    assert {f.technique_id for f in findings} == set(gt["expected_techniques"])


def test_no_false_positives_on_benign_records():
    events, findings, _, by_ref = run_case(str(_case()))
    gt = truth(_case())
    planted = {by_ref[r["raw_ref"]].id for r in gt["records"]}
    flagged = {i for f in findings for i in f.event_ids}
    assert flagged <= planted, sorted(flagged - planted)[:5]


def test_expected_confidence_examples():
    _, findings, _, _ = run_case(str(_case()))
    conf = {f.technique_id: f.confidence for f in findings}
    assert conf["T1070.001"] == "high" and conf["T1562.008"] == "high" and conf["T1003.001"] == "high"
    assert conf["T1558.003"] == "low"                                       # Kerberoast alone is weak evidence

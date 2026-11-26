"""Demo case 1 (FIR-1427/2027, synthetic): T1078, T1021, T1530 must link to r.mehta / 45.77.12.9."""

from evidence_helpers import CASE1, run_case, tmp_case1, truth
from vai.evidence import timeline
from vai.evidence.common import get_field

ATTACK_IP, USER = "45.77.12.9", "r.mehta"


def _case():
    path = CASE1 if (CASE1 / "windows_security.jsonl").exists() else tmp_case1(15000)
    from pathlib import Path
    return Path(path)


def test_size_and_clean_ingest():
    events, _, report, _ = run_case(str(_case()))
    assert 5000 <= len(events) <= 50000
    assert report["total_errors"] == 0
    assert {e.source for e in events} == {"windows", "linux", "aws"}
    assert len({e.id for e in events}) == len(events)                       # ids unique
    assert any(e.id.startswith("W-") for e in events) and any(e.id.startswith("L-") for e in events) and any(e.id.startswith("A-") for e in events)


def test_three_techniques_found_high_and_linked():
    events, findings, _, by_ref = run_case(str(_case()))
    ev_by_id = {e.id: e for e in events}
    for tech, source in (("T1078", "windows"), ("T1021", "linux"), ("T1530", "aws")):
        hits = [f for f in findings if f.technique_id == tech and f.confidence == "high"]
        assert len(hits) == 1, f"{tech}: expected exactly one high finding, got {len(hits)}"
        evs = [ev_by_id[i] for i in hits[0].event_ids]
        assert evs and all(e.user == USER and e.source == source for e in evs if e.ip)
        assert all(e.user == USER for e in evs)
        assert {e.ip for e in evs if e.ip} == {ATTACK_IP}
        assert ATTACK_IP in hits[0].title and USER in hits[0].title and "3 sources" in hits[0].title


def test_findings_match_ground_truth_exactly():
    """Every planted attack record is covered, and no HIGH/MEDIUM finding contains a non-attack record."""
    events, findings, _, by_ref = run_case(str(_case()))
    gt = truth(_case())
    attack = {by_ref[r["raw_ref"]].id for r in gt["records"] if r["tag"] in ("T1078", "T1021", "T1530")}
    covered = {i for f in findings if f.confidence == "high" for i in f.event_ids}
    assert attack == covered, (sorted(attack - covered), sorted(covered - attack))
    attack_all = {by_ref[r["raw_ref"]].id for r in gt["records"]}
    for f in findings:
        if f.confidence in ("high", "medium"):
            assert set(f.event_ids) <= attack_all, f.title


def test_decoys_and_scanners_stay_low():
    events, findings, _, by_ref = run_case(str(_case()))
    gt = truth(_case())
    decoy_ids = {by_ref[d["raw_ref"]].id for d in gt["decoys"]}
    touched = [f for f in findings if decoy_ids & set(f.event_ids)]
    assert touched and all(f.confidence == "low" for f in touched)          # hotel-IP login/download: seen, but low
    brute = [f for f in findings if f.technique_id == "T1110"]
    assert brute and all(f.confidence == "low" for f in brute)


def test_timeline_is_attack_story_in_order():
    events, findings, _, _ = run_case(str(_case()))
    story = timeline(findings, events, min_confidence="high")
    assert [f.technique_id for f in story] == ["T1078", "T1021", "T1530"]
    # same result via the contract signature timeline(findings): times come from the latest correlate() call
    from vai.evidence import correlate
    findings = correlate(events)
    assert [f.technique_id for f in timeline(findings, min_confidence="high")] == ["T1078", "T1021", "T1530"]
    full = timeline(findings, events)
    ts = {e.id: e.ts_utc for e in events}
    firsts = [min(ts[i] for i in f.event_ids) for f in full]
    assert firsts == sorted(firsts)


def test_credential_file_read_is_inside_t1021():
    events, findings, _, _ = run_case(str(_case()))
    f = next(f for f in findings if f.technique_id == "T1021" and f.confidence == "high")
    ev = {e.id: e for e in events}
    names = [e.action.split(" | ")[0] for e in map(ev.get, f.event_ids)]
    assert names.count("ssh_accepted") == 1 and names.count("sudo_command") == 2


def test_same_seed_same_files():
    from vai.evidence.tools.generate_case1 import generate_case
    import tempfile, hashlib
    from pathlib import Path
    a, b = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
    generate_case(a, 6000, 5); generate_case(b, 6000, 5)
    h = lambda d: {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.iterdir())}
    assert h(a) == h(b)

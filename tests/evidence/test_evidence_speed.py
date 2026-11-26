"""Speed sanity check on 100,000 synthetic records (generous limit; real numbers go to results/evidence/)."""
import time

from evidence_helpers import tmp_case1


def test_100k_records_ingest_and_correlate_under_limit():
    from vai.evidence import correlate, ingest
    d = tmp_case1(100000)
    t0 = time.perf_counter()
    events = ingest(d)
    t1 = time.perf_counter()
    findings = correlate(events)
    t2 = time.perf_counter()
    assert len(events) == 100000
    assert {"T1078", "T1021", "T1530"} <= {f.technique_id for f in findings if f.confidence == "high"}
    assert (t1 - t0) < 60 and (t2 - t1) < 60, (t1 - t0, t2 - t1)

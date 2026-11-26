# vai.evidence (Claude 1) - v1

Evidence layer: log files -> `Event` -> `Finding` -> timeline.  Windows (EVTX/JSON), Linux auth.log, AWS CloudTrail.

## Quick start (repo root, Python 3.11)
```
pip install pydantic pytest
python -m pytest tests/evidence -q                    # all tests
python -m vai.evidence.tools.make_results             # results/evidence/*  (json, txt, svg)
python -m vai.evidence.tools.benchmark                # speed note for 100k records
python -m vai.evidence.tools.generate_case1 --records 20000   # regenerate case 1 (same seed => same files)
```
If `vai/common/models.py` (Claude 0) is not in the repo yet, run with `PYTHONPATH=dev_mock:.` (Windows PowerShell: `$env:PYTHONPATH="dev_mock;."`).
`tests/evidence/conftest.py` does this automatically for pytest. `dev_mock/` must NOT be merged.

## Use in code
```python
from vai.evidence import ingest, correlate, timeline, timeline_text, hash_files, ingest_with_report
events   = ingest("data/sample/case_fir_1427")      # file or folder or list of paths
findings = correlate(events)
story    = timeline(findings, events, min_confidence="medium")
print(timeline_text(findings, events, min_confidence="medium"))
```
Extras: `hash_files(paths)` (SHA-256 per file, for ledger / BSA S.63), `ingest_with_report()` (counts, errors, hashes),
`EVIDENCE_LIMITATIONS` (standard limitation sentences for every conclusion).

## Conventions (other packages rely on these)
| Item | Rule |
|---|---|
| Event ids | `W-<EventRecordID>`, `L-<line number, continued across files>`, `A-<record index, continued across files>`; duplicate -> `-2` suffix |
| `raw_ref` | `<file>#line=N` / `#index=N` / `#record=N` |
| `ts_utc` | ISO UTC string `2027-03-14T15:42:07.123Z` |
| `user` | lower-case, domain removed; `""` if unknown. `ip` / `host` are `""` if unknown (never None) |
| `action` | `name \| key=value \| ...` e.g. `s3:GetObject \| access_key=AKIA.. \| bucket=..` |
| Finding confidence | high = same user+IP in 3 sources; medium = 2 sources (or same IP in 3); low = otherwise / rule-only weak hit |
| Finding ids | `F-0001`.. in time order |

Techniques emitted: T1078, T1021 (SSH login + credential-file read, per demo story), T1530, T1110 and 20 more (see `rules.py`).
All are suggestions for the analyst to confirm. Not proof of intent.

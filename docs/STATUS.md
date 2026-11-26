# STATUS

Last update: v1 — 27 Nov 2026, ~03:10 IST — all 5 packages merged by Claude 0.

Overall: ~45%

| Package | Owner | State | Notes |
|---|---|---|---|
| vai/common | Claude 0 | Done | contract v1.1 (`VerifyResult.problems` added) |
| vai/evidence | Claude 1 | Done, 1 fix | 1 test assumes `ts_utc` is datetime (contract: str). Case 2 data is recreated, not the real public samples yet. |
| vai/ledger | Claude 2 | Done, 1 fix | put readable reasons in `problems`, numbers only in `missing_steps`. Completeness protocol must match Agent's. |
| vai/agent | Claude 3 | Fix needed | must use `ledger.commit_plan/step_started/step_finished`; `approve()` must also require ledger completeness ok. |
| vai/legal | Claude 4 | Done, small glue by Claude 0 | report capped record IDs per step (was crashing on 15k IDs). |
| vai/web | Claude 5 | Done | must switch from fallback models to real `vai.common.models`; show `problems`. |

## Test results (real pydantic + pytest)

- pytest: **134 passed, 2 failed** (owner fixes listed above).
- Integration (`scripts/integration_run.py`), both demo cases: **13/14 stages pass**.
  Only failing stage: `ledger.verify_completeness` on a clean run (`PLAN_HASH_INVALID`, `PLAN_MISMATCH`):
  Agent writes its plan as `{"plan": [...]}` with its own hash; Ledger expects `commit_plan()` format.
- Tamper edit / delete / insert: detected in both cases.

## Glue changes by Claude 0 (in other packages)

- `vai/legal/report.py`: agent-steps table shows first 8 record IDs + "(+N more, full list in ledger)".
- Not merged: `dev_mock/` (marked DO NOT MERGE). `README_evidence.md` moved to `vai/evidence/`.

## STATUS block format each Claude must send

```
STATUS <package> v<N>
Done:
Pending:
Tests: <how many, passing?>
Data files added (paths):
Contract change request: none | <exact change + reason>
Questions for Claude 0:
```

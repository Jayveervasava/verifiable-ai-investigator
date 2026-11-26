# STATUS

Last update: v0 — 27 Nov 2026 (IST) — repo set up by Claude 0.

Overall: 10% (setup done; no package code received yet)

| Package | Owner | State | Notes |
|---|---|---|---|
| vai/common | Claude 0 | Done | models.py (contract v1), canon.py helper, tests |
| vai/evidence | Claude 1 | Pending | waiting for zip |
| vai/ledger | Claude 2 | Pending | waiting for zip |
| vai/agent | Claude 3 | Pending | waiting for zip |
| vai/legal | Claude 4 | Pending | waiting for zip |
| vai/web | Claude 5 | Pending | waiting for zip |

Contract changes: none (v1).

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

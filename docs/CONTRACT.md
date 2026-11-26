# CONTRACT (v1, frozen) — Verifiable AI Investigator

Owner: **Claude 0** (coordinator). Source of truth: `vai/common/models.py`.
Each package lives **only** in its own folder. Do not edit `vai/common/` or another team's folder.
Need a change? Write it under *Contract change request* in your STATUS block.

## Models (`vai.common.models`)

```
Event{id, ts_utc, source(windows|linux|aws), host, user, ip, action, raw_ref}
Finding{id, technique_id, title, event_ids[], confidence(high|medium|low)}
LedgerEntry{seq, ts, kind(evidence|agent_step|conclusion|approval|report), actor, payload_hash, prev_hash, hash}
VerifyResult{ok, checked, broken_at, missing_steps[]}
AgentStep{n, tool, input_hash, output_hash, reasoning, record_ids[]}
LegalMatch{technique_id, offence, act, section, reason, source_url, status="suggested - officer confirms"}
Case{id, title, victim, officer, events[], findings[], steps[], legal[], approved}
```

Field types: all ids/hashes/timestamps are `str`; `seq`, `checked`, `n` are `int`; `broken_at: int | None`;
`missing_steps: list[int]` (= `AgentStep.n` values); `approved: bool = False`.

## Package APIs

| Package | Owner | API |
|---|---|---|
| `vai.evidence` | Claude 1 | `ingest(paths) -> list[Event]`; `correlate(events) -> list[Finding]`; `timeline(findings) -> list[Finding]` |
| `vai.ledger` | Claude 2 | `Ledger(db)`: `.append(kind, actor, payload) -> LedgerEntry`, `.verify() -> VerifyResult`, `.verify_completeness(plan, entries) -> VerifyResult`, `.merkle_proof(seq)`, `.entries()`; module funcs `verify_proof(p) -> bool`, `tamper_demo(db, seq, mode="edit"\|"delete"\|"insert")` |
| `vai.agent` | Claude 3 | `Agent(ledger, llm=None)`: `.run(case) -> Case`, `.plan(case)`, `.explain(case) -> list[{reason, record_ids, limitation}]`, `.approve(case, officer)` |
| `vai.legal` | Claude 4 | `map_techniques(ids) -> list[LegalMatch]`; `case_report_pdf(case, ledger) -> bytes`; `s63_draft_pdf(case, ledger) -> bytes` |
| `vai.web` | Claude 5 | FastAPI `app` (importable as `vai.web.app` or `vai.web.app:app`). Routes: `GET /api/cases`, `GET /api/cases/{id}`, `POST /api/cases/{id}/run`, `POST .../verify`, `POST .../tamper-demo`, `GET .../why`, `POST .../approve`, `GET .../report`, `GET .../s63` |

All functions must be importable from the package root (e.g. `from vai.ledger import Ledger, tamper_demo, verify_proof`).

## Conventions (recommended — tell Claude 0 if your code already differs)

- Timestamps: ISO‑8601 UTC with `Z`, e.g. `2027-03-12T09:12:04Z`. Hash: SHA‑256 lowercase hex.
- Canonical hashing: use `vai.common.canon.hash_payload(obj)` (sorted-key compact JSON, UTF‑8).
- Genesis `prev_hash` = `"0"*64` (`vai.common.canon.GENESIS_HASH`).
- Case IDs contain `/` (e.g. `FIR-1427/2027`); web routes must URL‑encode (`FIR-1427%2F2027`) or use a slug `FIR-1427-2027`.

## Completeness design (Claude 2 + Claude 3 — this is the paper's core)

1. `Agent.plan(case)` returns the ordered list of planned steps (at least `n` and `tool` each).
   `Agent.run` **appends the plan to the ledger first** (kind `agent_step`, actor `agent`, payload `{"plan": [...]}`)
   before executing any step.
2. Every tool call is executed through the ledger (the agent never writes SQLite itself). Payload of each
   `agent_step` entry = the full `AgentStep` dump.
3. `verify_completeness(plan, entries)`: two‑way reconciliation — every planned `n` has exactly one executed
   entry (else listed in `missing_steps`), no executed step outside the plan, step order matches seq order.
   Must also be `ok=False` for **edited / deleted / inserted / reordered** steps.
4. Offline mode must be **deterministic**: same input → same `output_hash`, so a verifier can replay a step and
   catch a *faked* output even when the chain itself is valid.
5. `explain()` reasons may only cite `record_ids` that exist in `case.events`; each item has a `limitation`.

## Honesty rules (all packages)

Law sections are `"suggested - officer confirms"`. Say *verifiable*, never *admissible*. Demo names are fictional.
Never claim police use this. Public/synthetic data only. No secrets in code.

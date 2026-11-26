# vai.ledger (Claude 2)

Tamper-evident, hash-chained, append-only ledger (SQLite). Python 3.11, no extra packages
besides pydantic (contract models). Set `LEDGER_HMAC_KEY` (otherwise an INSECURE dev key + warning).

## Contract API
```python
from vai.ledger import Ledger, verify_proof, tamper_demo, copy_db
led = Ledger("case.db")                       # or Ledger(path, hmac_key="...")
e = led.append("evidence", "evidence:ingest", {"file": "x.evtx", "sha256": "..."})   # -> LedgerEntry
led.verify()                                  # -> VerifyResult (broken_at = first broken seq)
led.verify_completeness(plan, entries=None)   # -> VerifyResult (missing_steps = readable problems)
led.entries(); led.merkle_root(); p = led.merkle_proof(seq); verify_proof(p, trusted_root)
tamper_demo(copy_db(led), seq, mode="edit|delete|insert|reorder")   # ALWAYS on a copy
led.export_package("case_export.zip", case_id="FIR-1427/2027")
```
kind is one of: evidence, agent_step, conclusion, approval, report. Payload = any JSON-able dict
(pydantic models are converted). Datetimes must be ISO strings.

## Rules for the AGENT (Claude 3) so completeness works
```python
led.commit_plan(plan, actor)                              # BEFORE running anything; plan=[{n, tool, input_hash?}]
led.step_started(n, tool, input_hash, actor)              # before every tool run
led.step_finished(n, tool, output_hash, actor, record_ids, reasoning)   # after every tool run
audit = led.full_audit(plan)                              # chain + completeness + merkle root
```
## For Legal/Reports (Claude 4) and Web (Claude 5)
* `led.anchor()` -> {seq, hash, merkle_root}: print it in the report; later `led.verify(expected_head=anchor)`.
* `led.merkle_proof(seq)` is JSON-able; show `root` in reports. `led.verify_with_reason()` -> (VerifyResult, text).
* Tamper demo endpoint must use `copy_db(led)` - never the real case ledger.

## Limits (be honest in reports)
* HMAC key + DB together can be rewritten by whoever holds BOTH; keep the key off the DB machine and
  store the anchor/root outside (report, email). Ledger proves records are unchanged since written
  (verifiable); it does not prove the evidence itself is true.
* Completeness proves the logged steps match the committed plan; it cannot see work done outside the agent.

## Run
`python -m vai.ledger.demo` and `python -m vai.ledger.bench` write to `results/ledger/`.
Tests: `pytest tests/ledger` (plain unittest style, also runs with `python -m unittest`).

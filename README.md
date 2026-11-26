# Verifiable AI Investigator

> Research prototype · synthetic and public data only · not used by any police force

## Abstract

Verifiable AI Investigator helps police cyber cells investigate cyber crime with an AI agent whose every step is recorded in a tamper-evident, hash-chained ledger. It collects Windows, Linux and AWS cloud logs, links them by user, IP and credential into one attack timeline, maps each step to MITRE ATT&CK and to suggested IT Act 2000 / BNS 2023 sections, and explains its conclusion with the exact records used. Any change to evidence or AI steps is detected instantly, and the system prepares a case report and a Section 63 (BSA 2023) certificate draft for the officer to review and sign. Officers stay in control: nothing is final until they approve.

## What makes it different

Most agent logs prove that a saved record was not *changed*. This project also checks that the agent did not
*hide, skip, insert, reorder or fake* a step (completeness): the plan is committed to the ledger before the agent
runs, every step is recorded by the ledger (not by the agent), and offline steps can be replayed to check their
outputs. See [docs/NOVELTY.md](docs/NOVELTY.md).

## Repository layout

```
vai/common    shared data contract (models.py)      – Claude 0
vai/evidence  log ingest, correlation, timeline      – Claude 1
vai/ledger    hash chain, Merkle proofs, completeness – Claude 2
vai/agent     investigator agent (offline rules, optional LLM) – Claude 3
vai/legal     law mapping, case report, s.63 draft   – Claude 4
vai/web       FastAPI + plain HTML/JS UI             – Claude 5
data/sample   synthetic + public demo data
results/      experiment outputs and figures
docs/         CONTRACT, STATUS, NOVELTY, ui-preview
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest
python scripts/integration_run.py
```

Optional LLM: copy `.env.example` to `.env` and set `LLM_API_KEY`. Without it, the agent runs fully offline with
rule-based reasoning.

## Honesty notes

- Law sections are **suggestions — the officer confirms**.
- The system produces **verifiable** records; whether evidence is admissible is for a court to decide.
- Every conclusion lists the record IDs it used and its limitations.
- All names, companies and FIR numbers in demos are fictional.

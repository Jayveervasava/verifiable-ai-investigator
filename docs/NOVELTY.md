# NOVELTY.md — Prior work check and what is new

Literature check done on 27 Nov 2026. Links were opened/searched on that date. This file is an engineering
positioning note for the project, not paper text.

## 1. The core problem in one line

A hash chain proves that **what was written was not changed** (integrity). It does **not** prove that
**everything that happened was written** (completeness). An AI agent that can skip, hide or invent a step can
still produce a perfectly valid hash chain. Our project targets completeness for an AI agent that investigates
cyber-crime evidence, inside an Indian legal workflow.

## 2. Closest prior work

| # | Work | What it does | What it does NOT do (gap for us) |
|---|------|--------------|----------------------------------|
| 1 | **IETF Agent Audit Trail (AAT)**, draft-sharif-agent-audit-trail (‑00 Mar 2026 … ‑07 Nov 2026) — https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/ | Standard JSON log record for agent actions; SHA‑256 hash chaining over RFC 8785 canonical JSON, optional ECDSA signatures; later revisions add pre‑execution recording, "recording independence" (self vs independent recorder), replay protection, external timestamp anchoring, and a mandatory "principal" field. Maps to EU AI Act, SOC 2, ISO 42001. | A **log format**, not a verifier. No method to prove that a *planned* investigation was fully executed; no evidence-bound explanations; no forensic / legal workflow; no Indian law (BSA s.63). |
| 2 | **IETF Agent Auditing Architecture**, draft-kuehlewind-audit-architecture (‑00 May 2026, ‑01 Sep 2026) | Architecture for auditing delegation chains across agents, sub-agents and services. | Architecture only; no completeness proof or experiments; no forensic domain. |
| 3 | **"Agent Flight Recorder"** family — e.g. cwwjacobs/agent-flight-recorder, `agent-flight-recorder` (PyPI), `llm-run-recorder`/AgentRewind, Reflight, AIR Blackbox, Honeycomb Agent Timeline | Record every LLM/tool call, replay deterministically, diff runs, turn failures into regression tests. | Built for **debugging / cost**, not evidence. Mostly no tamper-evidence, no omission detection, no legal output. Logs live on the same host the agent controls. |
| 4 | **NovaFabric** — arXiv 2609.12582 and 2610.34594; PyPI `novafabric` | "Black-box recorder" producing sealed, replayable, diffable Run Capsules; W3C‑PROV lineage; tamper-evident sealing (NovaSeal). Authors state the contribution is integration at agent-session granularity, not new cryptography. | General-purpose (not forensic). Integrity of what was captured; no explicit **plan-vs-execution completeness** check, no evidence-bound conclusions, no officer approval / legal certificate workflow. Authors say they did not benchmark against other tools. |
| 5 | **PROVSEEK** — Mukherjee & Kantarcioglu, arXiv 2508.21323 (Aug 2025) | LLM agent for provenance-graph forensics of APTs (DARPA data): RAG over CTI + provenance DB queries, multi-agent roles, CoT; reports +34% precision/recall for intel extraction and +22%/29% detection precision/recall vs baselines. | Good **investigator**, but its own reasoning steps are **not recorded in a tamper-evident ledger**; no proof that the agent did not skip or fake a step; no chain of custody / court certificate. |
| 6 | **"LLM Agents Can Easily Tamper With Their Own Traces"** — Qin et al., arXiv 2609.30266 (24 Sep 2026) | Shows agents in Claude Code, Codex, Antigravity, Open Code, Grok Build deleted/modified their own traces when asked, under external attack, and even spontaneously under reward pressure; recommends logging through an independent interception mechanism outside agent control. | A **problem paper** (attack study). Does not build a verifiable forensic agent. It is our strongest *motivation*. |
| 7 | **"Auditable Claims about AI Agents"** — Zhao et al., arXiv 2610.07459 (≈Sep 2026) and **"Hearsay"** (Dai et al., arXiv 2609.32495, as reported in #7) | States formally that signatures/hash chains over entries the audited party submits cannot prove completeness; reports that a harness-kept hash chain caught 0 of 28 injected omissions/fabrications while an outside log caught 28/28. Requires an independent record + two-way reconciliation. | Position/theory + generic measurement. **No forensic agent, no Indian legal workflow.** Important: this means *"integrity ≠ completeness" is already known* — we must not claim to discover it. |
| 8 | **AgentDFIR** (github.com/efij/AgentDFIR) | DFIR **of** AI agents (investigating what an agent did on a machine), tamper-evident case files. | Opposite direction: forensics of agents, not an agent doing forensics. |
| 9 | **Agentropix‑SIFT** (Devpost hackathon) | "LLM at the edge, determinism inside": deterministic triage, SHA‑256 evidence binding + HMAC seal over report and audit log. | Very close in spirit (deterministic core, sealed log). But hackathon-level, no completeness proof vs a committed plan, no experiments, no Indian law. |
| 10 | LLM-for-forensics papers — arXiv 2504.02963 (survey), 2602.20202 (DFKG reliability), 2409.02572 (timeline analysis + RAG) | Show LLMs help forensic extraction/timelines; the survey notes chain-of-custody problems when intermediate LLM outputs are not logged and inconsistent timelines across runs. | Accuracy-focused; no verifiable step record; no completeness. |
| 11 | India law context — BSA 2023 s.63(4) + Schedule; *Pune Bar Association v. Union of India* (SC, 2026) | Certificate has **Part A (party)** and **Part B (expert)**, both with hash values (MD5/SHA‑1/SHA‑256). SC upheld s.63(4) and said persons skilled in computer science/cyber forensics (not only s.79A IT Act examiners) may sign Part B. | No existing tool we found auto-prepares a s.63 Part A + Part B **draft** directly from a verified ledger with an officer-approval gate. |

## 3. What is new in our project (claimed contributions)

Primitives (SHA‑256 chain, Merkle proofs, HMAC) are **not** new. The novelty is in *what we prove* and *where*:

1. **Completeness of agent steps, not only integrity.**
   - The agent's **plan is committed to the ledger before execution** (pre-commitment).
   - Every tool call goes **through the ledger's recorder**, which the agent cannot bypass or write to directly
     (independent recorder, as #6/#7 recommend).
   - `verify_completeness(plan, entries)` does **two-way reconciliation**: every planned step has exactly one
     executed entry (catches *deleted/hidden* steps) and every executed entry belongs to the plan (catches
     *inserted* steps); sequence numbers and prev-hash catch *reordered* steps.
2. **Fake-step detection by deterministic replay.** In offline (rule-based) mode every step is deterministic, so
   a verifier re-runs the step on the hashed inputs and checks `output_hash`. A step whose recorded output was
   invented (even if the chain is valid) fails replay. For the optional LLM mode we record and replay the LLM
   response (cassette) and state honestly that the LLM's internal reasoning is not provable.
3. **Evidence-bound explanations.** Every conclusion lists the exact `record_ids` it used; the verifier checks
   that those IDs exist in hashed evidence entries (no "hallucinated" evidence) plus a stated limitation.
4. **Indian legal workflow on top of a verified ledger.** Technique → suggested IT Act 2000 / BNS 2023 sections
   ("suggested – officer confirms"), officer approval recorded as a ledger entry, and an auto-drafted BSA s.63
   certificate with **both Part A and Part B**, filled from ledger hashes. Nothing is final before approval.
5. **Measured, not just designed.** Experiments on edited / deleted / inserted / reordered / faked steps, explanation
   correctness vs ground truth, law-mapping accuracy, and performance at scale (see §5).

## 4. Honest risks to novelty

- The integrity-vs-completeness gap and the "independent recorder" fix are **already stated** by #6 and #7. Our
  claim must be: *first concrete, evaluated instantiation for an AI DFIR investigator with an Indian legal workflow*,
  plus deterministic replay for fake-step detection.
- If the ledger runs on the same machine/process as the agent, a fully compromised host can still rewrite
  everything. Mitigation to implement: periodic **external anchoring** of the Merkle root (e.g., printed in the
  officer-signed s.63 draft, or exported to a second store) — and say clearly what is out of scope.
- Synthetic + public datasets only; no claim of real police use; "verifiable", never "admissible".

## 5. Experiments this file commits us to (results go to `results/`)

| Exp | Question | Metric |
|-----|----------|--------|
| E1 | Does verify / verify_completeness catch edited, deleted, inserted, reordered, faked steps? Baseline: plain hash chain kept by the agent. | detection rate, false-positive rate, per attack type (N randomized trials) |
| E2 | Is the "why" explanation correct? | precision/recall of cited record IDs vs ground-truth attack records; % conclusions with a limitation |
| E3 | Is the law mapping right? | accuracy of suggested sections vs a hand-labelled table of techniques |
| E4 | Does it scale? | append/verify time and DB size for 10³…10⁶ events; Merkle proof size/time |

## Sources

- IETF AAT draft: https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/
- IETF audit architecture: https://www.ietf.org/archive/id/draft-kuehlewind-audit-architecture-00.html
- Agent Flight Recorder: https://github.com/cwwjacobs/agent-flight-recorder ; https://pypi.org/project/agent-flight-recorder ; https://pypi.org/project/llm-run-recorder/ ; https://pypi.org/project/reflight/
- NovaFabric: https://arxiv.org/pdf/2609.12582 ; https://arxiv.org/pdf/2610.34594 ; https://pypi.org/project/novafabric/
- PROVSEEK: https://arxiv.org/abs/2508.21323
- Trace tampering: https://arxiv.org/pdf/2609.30266
- Auditable Claims: https://arxiv.org/pdf/2610.07459 (cites Hearsay, arXiv 2609.32495)
- AgentDFIR: https://github.com/efij/AgentDFIR ; Agentropix: https://devpost.com/software/agentropix-mcp-agentic-forensics-incident-response
- LLM + forensics: https://arxiv.org/pdf/2504.02963 ; https://arxiv.org/abs/2602.20202 ; https://arxiv.org/pdf/2409.02572v2.pdf
- BSA s.63 / Pune Bar Association: https://www.verdictum.in/supreme-court/qualification-section-39-bsa-not-restricted-section-79a-it-act-examiners-forensics-sign-part-b-certificate-1614860 ; https://www.livelaw.in/articles/bharatiya-sakshya-adhiniyam-transformed-digital-evidence-552681

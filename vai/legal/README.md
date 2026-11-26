# vai.legal (Claude 4) - law mapping and PDF reports

| Function | What it does |
|---|---|
| `map_techniques(ids)` | MITRE technique ids -> `[LegalMatch]` (IT Act 2000 / BNS 2023), status always "suggested - officer confirms" |
| `case_report_pdf(case, ledger, *, plan=None, explanations=None, generated_at=None)` | Case report PDF (timeline, law, conclusion, limitations, ledger root, integrity, completeness, approval) |
| `s63_draft_pdf(case, ledger, *, expert=None, plan=None, generated_at=None)` | Draft BSA 2023 s.63 certificate, Part A (party) + Part B (expert), watermark "DRAFT - to be reviewed and signed" |

Law data: `data/mitre_to_law.yaml` (each entry has reason, indiacode.nic.in source, doubt).
Run tests: `pytest tests/legal`. Sample output: `python -m vai.legal.cli --out results/legal`.

Rules kept: says "verifiable" never "admissible"; unknown facts are left blank for the signatory;
a failed ledger check is shown in red and is never reported as OK.
Needs: reportlab, pyyaml (pypdf and pdfplumber for tests).

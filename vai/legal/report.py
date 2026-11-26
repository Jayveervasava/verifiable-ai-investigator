"""case_report_pdf(case, ledger) -> bytes

Builds the investigation report: case details, timeline with MITRE technique
and suggested law, conclusion with record ids, limitations, ledger root,
integrity + completeness result and approval status.

Wording rule: the report says "verifiable"; it never claims a court outcome.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import mapping
from ._access import (as_list, collect_ledger, fmt_ist, fmt_utc, g, short_hash, sort_key_ts)
from ._compat import STATUS_TEXT
from ._pdf import (CONTENT_W, PR, P, banner, bullet, build_pdf, esc, grid_table, kv_table)

LIMITATIONS = [
    "Findings come from the log files supplied to the system only. Logs may be incomplete, rotated or already altered before they were collected.",
    "An IP address or user name in a log is not the identity of a person. It may be a VPN, a proxy, a shared account or a compromised machine.",
    "Timestamps are as written by the source systems. Clock errors and time-zone settings were not independently checked.",
    "A MITRE ATT&CK technique is an analytic label. It is not a legal conclusion.",
    "Law sections are suggestions only (status: suggested - officer confirms). This is not legal advice and the system does not decide guilt.",
    "The ledger shows that recorded items have not changed since they were recorded. It cannot show that the original logs were genuine before they were collected.",
    "The completeness check compares the ledger with the agent's declared plan. It cannot detect work that was never planned.",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _law_cell(matches) -> str:
    return "; ".join(f"{m.act} {m.section}" for m in matches) or "no mapping available"


def case_report_pdf(case, ledger, *, plan=None, explanations=None, generated_at=None) -> bytes:
    """Create the case report.

    Optional extras (the contract call `case_report_pdf(case, ledger)` still works):
      plan          planned steps (Agent.plan(case)) so completeness can be checked;
                    if None, case.plan is used, else completeness shows NOT CHECKED.
      explanations  output of Agent.explain(case): [{reason, record_ids, limitation}].
      generated_at  datetime, fixed value gives byte-identical PDFs (for tests).
    """
    generated_at = generated_at or _now()
    if plan is None:
        plan = g(case, "plan")
    view = collect_ledger(ledger, plan)

    events = as_list(g(case, "events"))
    findings = as_list(g(case, "findings"))
    steps = as_list(g(case, "steps"))
    ev_by_id = {str(g(e, "id")): e for e in events}
    approved = bool(g(case, "approved", False))
    approvals = view.of_kind("approval")
    case_id, officer = g(case, "id", ""), g(case, "officer", "")

    story = [P("Case Report - Verifiable AI Investigator", "title"),
             P(f"Case {case_id}: {g(case, 'title', '')}", "sub")]

    # --- approval banner ---------------------------------------------------
    if approved and approvals:
        a = approvals[-1]
        story.append(banner(f"Approved by officer {officer} (ledger approval record seq {g(a, 'seq')}).", "green"))
    elif approved:
        story.append(banner("WARNING: case is marked approved but NO approval record was found in the ledger. "
                            "Treat this report as not approved.", "red"))
    else:
        story.append(banner("DRAFT - NOT YET APPROVED BY THE OFFICER. This report is not final.", "amber"))

    # --- 1 case details ----------------------------------------------------
    story += [P("1. Case details", "h1"), kv_table([
        ("Case / FIR no.", str(case_id)), ("Title", g(case, "title", "")),
        ("Victim / complainant", g(case, "victim", "")), ("Investigating officer", officer),
        ("Approval status", "APPROVED" if approved and approvals else "NOT APPROVED"),
        ("Counts", f"{len(events)} events, {len(findings)} findings, {len(steps)} agent steps, "
                   f"{len(view.entries)} ledger entries"),
        ("Report generated", f"{fmt_utc(generated_at)} / {fmt_ist(generated_at)}"),
        ("Prepared by", "Verifiable AI Investigator (AI-assisted). The officer must review every item."),
    ])]

    # --- 2 timeline --------------------------------------------------------
    def first_ts(f):
        times = [sort_key_ts(g(ev_by_id.get(str(i)), "ts_utc")) for i in as_list(g(f, "event_ids"))]
        return min(times) if times else float("inf")

    ordered = sorted(findings, key=first_ts)
    rows, all_matches = [], []
    for n, f in enumerate(ordered, start=1):
        tid = g(f, "technique_id", "")
        matches = mapping.map_techniques([tid])
        all_matches.extend(matches)
        evs = [ev_by_id.get(str(i)) for i in as_list(g(f, "event_ids"))]
        evs = [e for e in evs if e is not None]
        t0 = min(evs, key=lambda e: sort_key_ts(g(e, "ts_utc"))) if evs else None
        when = (f"{esc(fmt_utc(g(t0, 'ts_utc')))}<br/>{esc(fmt_ist(g(t0, 'ts_utc')))}" if t0 else "unknown")
        name = mapping.technique_name(tid)
        rows.append([str(n), PR(when, "cell"),
                     f"{tid} {name}".strip(), f"{g(f, 'id', '')}: {g(f, 'title', '')}",
                     str(g(f, "confidence", "")), ", ".join(map(str, as_list(g(f, "event_ids")))),
                     _law_cell(matches)])
    story.append(P("2. Timeline (MITRE ATT&CK technique and suggested law)", "h1"))
    if rows:
        story.append(grid_table(["#", "Time", "MITRE technique", "Finding", "Conf.", "Event ids", "Suggested law"],
                                rows, [6, 27, 26, 36, 14, 25, 40]))
    else:
        story.append(P("No findings are recorded for this case."))

    used = []
    for f in ordered:
        for i in as_list(g(f, "event_ids")):
            if str(i) in ev_by_id and str(i) not in used:
                used.append(str(i))
    if used:
        story.append(P("Events referenced by the findings", "h2"))
        story.append(grid_table(
            ["Id", "Time (UTC)", "Source / host", "User", "IP", "Action", "Raw reference"],
            [[i, fmt_utc(g(ev_by_id[i], "ts_utc")), f"{g(ev_by_id[i], 'source')} / {g(ev_by_id[i], 'host')}",
              g(ev_by_id[i], "user", ""), g(ev_by_id[i], "ip", ""), g(ev_by_id[i], "action", ""),
              g(ev_by_id[i], "raw_ref", "")] for i in used],
            [14, 26, 30, 17, 22, 38, 27]))

    # --- 3 suggested law ---------------------------------------------------
    story.append(P("3. Suggested legal provisions", "h1"))
    story.append(banner(f"All entries below are '{STATUS_TEXT}'. They are suggestions from a public-source "
                        "mapping that has not been reviewed by a lawyer.", "grey"))
    law = as_list(g(case, "legal")) or all_matches
    if law:
        story.append(grid_table(
            ["Technique", "Offence", "Act and section", "Why it may apply", "Source"],
            [[g(m, "technique_id"), g(m, "offence"), f"{g(m, 'act')} s.{g(m, 'section')}",
              g(m, "reason"), g(m, "source_url")] for m in law],
            [19, 36, 24, 56, 39]))
        doubts = []
        for m in law:
            d = mapping.doubt_for(g(m, "technique_id"), g(m, "act"), g(m, "section"))
            if d and d not in doubts:
                doubts.append(d)
        if doubts:
            story.append(P("Doubts to check before relying on the mapping", "h2"))
            story += [bullet(d) for d in doubts]
    else:
        story.append(P("No law mapping is available for the techniques in this case."))
    miss = mapping.unmapped([g(f, "technique_id") for f in findings])
    if miss:
        story.append(P("Techniques with no law mapping (officer to decide): " + ", ".join(miss)))

    # --- 4 conclusion ------------------------------------------------------
    story.append(P("4. Conclusion (proposal for the officer)", "h1"))
    if ordered:
        chain = " -> ".join(f"{g(f, 'technique_id')} ({g(f, 'title')})" for f in ordered)
        story.append(P(f"On the supplied records the system found {len(ordered)} finding(s) in this order: {chain}. "
                       "These are consistent with the activity described and are not a finding of guilt."))
    story.append(P("Each finding with the records it rests on", "h2"))
    for f in ordered:
        fid = str(g(f, "id", ""))
        evids = [str(i) for i in as_list(g(f, "event_ids"))]
        refs = [str(g(s, "n")) for s in steps
                if {str(r) for r in as_list(g(s, "record_ids"))} & ({fid} | set(evids))]
        low = " Confidence is not high; treat with extra care." if str(g(f, "confidence")) != "high" else ""
        story.append(bullet(f"{fid} ({g(f, 'technique_id')}, confidence {g(f, 'confidence')}): events "
                            f"{', '.join(evids) or 'none'}; agent steps {', '.join(refs) or 'none found'}.{low}"))
    concl = view.of_kind("conclusion")
    if concl:
        story.append(P("The conclusion is recorded in the ledger at seq " + ", ".join(str(g(c, "seq")) for c in concl) + "."))
    if explanations:
        story.append(P("Agent explanation", "h2"))
        for x in explanations:
            story.append(bullet(f"{g(x, 'reason', '')} | records: {', '.join(map(str, as_list(g(x, 'record_ids'))))} "
                                f"| limitation: {g(x, 'limitation', '')}"))

    # --- 5 limitations -----------------------------------------------------
    story.append(P("5. Limitations", "h1"))
    story += [bullet(t) for t in LIMITATIONS]

    def _short_ids(ids, k=8):
        ids = list(map(str, ids))
        return ", ".join(ids[:k]) + (f" (+{len(ids) - k} more, full list in ledger)" if len(ids) > k else "")

    # --- 6 agent steps -----------------------------------------------------
    story.append(P("6. Agent steps", "h1"))
    if steps:
        story.append(grid_table(
            ["Step", "Tool", "Input hash", "Output hash", "Reasoning", "Records"],
            [[str(g(s, "n")), g(s, "tool", ""), short_hash(g(s, "input_hash")), short_hash(g(s, "output_hash")),
              g(s, "reasoning", ""), _short_ids(as_list(g(s, "record_ids")))] for s in steps],
            [10, 24, 28, 28, 54, 30]))
    else:
        story.append(P("No agent steps recorded."))

    # --- 7 ledger ----------------------------------------------------------
    story.append(P("7. Ledger integrity and completeness", "h1"))
    if view.integrity_ok:
        integ = f"PASSED - {view.checked} entries checked, no break found."
    else:
        where = f" Chain breaks at seq {view.broken_at}." if view.broken_at is not None else ""
        integ = f"FAILED.{where} {view.integrity_error}".strip()
    comp = {"ok": "PASSED - every planned step has a matching ledger record.",
            "failed": "FAILED - planned steps missing from the ledger: " + (", ".join(map(str, view.missing_steps)) or "unspecified"),
            "not_checked": "NOT CHECKED - no plan was supplied, so completeness could not be tested.",
            "error": f"NOT CHECKED - the check could not run: {view.completeness_error}"}[view.completeness]
    story.append(banner("Integrity: " + integ, "green" if view.integrity_ok else "red"))
    story.append(banner("Completeness: " + comp, "green" if view.completeness == "ok" else
                        ("red" if view.completeness == "failed" else "amber")))
    story.append(kv_table([
        (view.root_label, view.root_value), ("Entries by kind", ", ".join(f"{k}: {v}" for k, v in sorted(view.kinds.items())) or "none"),
    ], widths=(45, 129)))
    if view.entries:
        story.append(P("Ledger entries", "h2"))
        story.append(grid_table(
            ["Seq", "Time (UTC)", "Kind", "Actor", "Payload hash", "Entry hash"],
            [[str(g(e, "seq")), fmt_utc(g(e, "ts")), g(e, "kind", ""), g(e, "actor", ""),
              short_hash(g(e, "payload_hash")), short_hash(g(e, "hash"))] for e in view.entries],
            [10, 36, 22, 30, 38, 38]))

    # --- 8 approval --------------------------------------------------------
    story.append(P("8. Officer approval", "h1"))
    if approved and approvals:
        a = approvals[-1]
        status = f"APPROVED - ledger record seq {g(a, 'seq')} at {fmt_utc(g(a, 'ts'))} by {g(a, 'actor', '')}."
    else:
        status = "NOT APPROVED - nothing in this report is final until the officer approves it."
    story.append(kv_table([("Status", status), ("Officer", officer),
                           ("Signature and date (printed copy)", "______________________________")]))
    story.append(P("This report is produced by software to make the investigation verifiable. It makes no claim about "
                   "what a court will accept; that is for the court.", "small"))

    wm = None if (approved and approvals) else "DRAFT - NOT APPROVED"
    return build_pdf(story, title=f"Case report {case_id}", author="Verifiable AI Investigator",
                     subject="Case report", watermark=wm,
                     footer=f"VAI case report {case_id} - AI-assisted, officer approval required")

"""s63_draft_pdf(case, ledger) -> bytes

Draft certificate under Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023,
following the two-part form in the Schedule:
  Part A - to be filled by the Party (person in charge of the device / record source)
  Part B - to be filled by the Expert

What the system can fill from the case and ledger is filled (record, device or
system type, how it was produced, hash values). Facts that only a human can
confirm (lawful control, proper working, ownership, make/model/serial, names,
signatures, date, place) are left as clearly marked blanks or unticked boxes.
Every page carries the watermark "DRAFT - to be reviewed and signed".
"""
from __future__ import annotations

from datetime import datetime, timezone

from ._access import as_list, collect_ledger, fmt_ist, fmt_utc, g, hash_algorithm
from ._pdf import (CONTENT_W, PR, P, banner, bullet, build_pdf, esc, grid_table, kv_table, mono)

WATERMARK = "DRAFT - to be reviewed and signed"
BLANK = "______________________________"
TODO = "[TO BE FILLED BY SIGNATORY]"
BOX, TICK = "[  ]", "[X]"

# event.source -> device/source type shown on the Schedule form
SOURCE_TYPE = {"windows": "Computer / Storage Media", "linux": "Server", "aws": "Cloud"}
FORM_TYPES = ["Computer / Storage Media", "DVR", "Mobile", "FlashDrive", "CD/DVD", "Server", "Cloud", "Other"]


def _ticks(selected: set[str]) -> str:
    return "   ".join(f"{TICK if t in selected else BOX} {t}" for t in FORM_TYPES)


def _hash_rows(evidence) -> list[list]:
    return [[str(i), str(g(e, "seq")), g(e, "actor", ""), fmt_utc(g(e, "ts")),
             hash_algorithm(str(g(e, "payload_hash", ""))), mono(g(e, "payload_hash", ""))]
            for i, e in enumerate(evidence, start=1)]


def s63_draft_pdf(case, ledger, *, expert=None, plan=None, generated_at=None) -> bytes:
    """Create the draft Section 63 certificate (Part A and Part B).

    expert        optional expert name to pre-fill in Part B (else left blank).
    plan          optional planned steps; only used for the completeness line in the annexure.
    generated_at  fixed datetime gives byte-identical output (tests).
    """
    generated_at = generated_at or datetime.now(timezone.utc)
    if plan is None:
        plan = g(case, "plan")
    view = collect_ledger(ledger, plan)
    evidence = view.of_kind("evidence")
    events = as_list(g(case, "events"))
    case_id, officer = g(case, "id", ""), g(case, "officer", "")

    sources = {str(g(e, "source")) for e in events}
    selected = {SOURCE_TYPE[s] for s in sources if s in SOURCE_TYPE}
    hosts = sorted({str(g(e, "host")) for e in events if g(e, "host")})
    refs: dict[str, int] = {}
    for e in events:
        ref = str(g(e, "raw_ref", "")).split("#")[0]
        if ref:
            refs[ref] = refs.get(ref, 0) + 1

    story = [P("Draft Certificate under Section 63(4)(c)", "title"),
             P("Bharatiya Sakshya Adhiniyam, 2023 - form in the Schedule (Part A: Party, Part B: Expert)", "sub"),
             P(f"Case {case_id}: {g(case, 'title', '')}", "sub")]

    # warnings first
    if not view.integrity_ok:
        story.append(banner("LEDGER INTEGRITY CHECK FAILED - do not sign this certificate until the ledger problem "
                            "is explained. " + (f"Chain breaks at seq {view.broken_at}. " if view.broken_at is not None else "")
                            + view.integrity_error, "red"))
    if not evidence:
        story.append(banner("No evidence entries were found in the ledger, so there are no hash values to certify.", "red"))
    story.append(banner("DRAFT. Items marked [TO BE FILLED BY SIGNATORY] or unticked boxes can only be confirmed by "
                        "the person signing. Nothing here is signed or final.", "amber"))

    story += [P("How to use this draft", "h1"),
              bullet("Auto-filled from the case and ledger: the record(s), the type of device or system, how the record was "
                     "produced, and the hash values."),
              bullet("Part A is for the party who produces the record (the person in charge of the device or record source). "
                     "Part B is for an expert, who checks the record and its hash values independently."),
              bullet("The wording below is a plain-language version of the Schedule form. Before signing, copy the final text "
                     "onto the official Schedule form as published in the Gazette / on indiacode.nic.in."),
              bullet("Enclose a hash report. Annexure 1 is the system's hash report; the expert should also attach the output "
                     "of their own hashing tool.")]

    story += [P("Record(s) covered by this certificate", "h1"),
              P("Evidence items registered in the ledger (hash taken when the item was recorded):")]
    if evidence:
        story.append(grid_table(["No.", "Ledger seq", "Recorded by", "Recorded at (UTC)", "Algorithm", "Hash value"],
                                _hash_rows(evidence), [9, 14, 26, 36, 18, 71]))
    if refs:
        story += [P("Source files referenced by the events in this case", "h2"),
                  grid_table(["Source file / reference", "Events using it"], [[k, str(v)] for k, v in sorted(refs.items())], [130, 44])]

    # ---------------- PART A ----------------
    story += [P("PART A - To be filled by the Party", "h1"),
              kv_table([
                  ("Name", officer + "   (taken from the case record; confirm or replace)"),
                  ("Son / daughter / spouse of", BLANK), ("Residing / employed at", BLANK),
                  ("Designation", BLANK)]),
              P("Digital device or record source from which the record was produced (ticked from the event sources "
                "in the case; the signatory must check):", "h2"),
              PR(esc(_ticks(selected)), "cell"),
              kv_table([
                  ("Other (specify)", BLANK), ("Make and model", TODO), ("Colour", BLANK), ("Serial number", TODO),
                  ("IMEI / UIN / UID / MAC / Cloud ID (as applicable)", TODO),
                  ("Other relevant information", "Hosts / systems seen in the events: " + (", ".join(hosts) or "none") + ".")], widths=(62, 112)),
              P("How the record was produced", "h2"),
              P(f"The event records were collected from the source files listed above and registered in the Verifiable AI "
                f"Investigator (VAI) ledger. For each item the ledger holds a hash value and a hash-chained entry. "
                f"The ledger holds {len(evidence)} evidence entr{'y' if len(evidence) == 1 else 'ies'} and "
                f"{view.kinds.get('agent_step', 0)} AI step record(s). The integrity check run on {fmt_utc(generated_at)} "
                f"{'passed' if view.integrity_ok else 'FAILED'} ({view.checked} entries checked). "
                f"The software produced the analysis and the report; the person signing is responsible for the statements "
                f"below."),
              P("Statements the signatory must personally confirm (tick only if true)", "h2")]
    for t in [
        "The device or record source was under my lawful control and was used regularly to create, store or process "
        "information for regular activities during the relevant period.",
        "Information of this kind was regularly fed into the device during the ordinary course of those activities.",
        "The device was working properly during that period. If it was ever not working properly or out of operation, "
        "it did not affect the record or its accuracy.",
        "The output reproduces, or is derived from, information fed into the device in the ordinary course of those activities.",
    ]:
        story.append(PR(f"{BOX} {esc(t)}", "body"))
    story += [PR(f"The device or record source is (tick as applicable):  {BOX} Owned   {BOX} Maintained   "
                 f"{BOX} Managed   {BOX} Operated   by me.", "body"),
              P("Hash value(s) of the electronic record(s)", "h2")]
    if evidence:
        story.append(grid_table(["No.", "Algorithm", "Hash value (SHA1 / SHA256 / MD5 / Other)"],
                                [[str(i), hash_algorithm(str(g(e, 'payload_hash', ''))), mono(g(e, "payload_hash", ""))]
                                 for i, e in enumerate(evidence, start=1)], [9, 22, 143]))
    story += [P("Hash report enclosed: Annexure 1 (and the signatory's own hash tool output, if any).", "small"),
              kv_table([("(Name and signature)", BLANK), ("Date (DD/MM/YYYY)", BLANK),
                        ("Time (IST), 24-hour format", BLANK + " hours"), ("Place", BLANK)], widths=(62, 112))]

    # ---------------- PART B ----------------
    story += [P("PART B - To be filled by the Expert", "h1"),
              kv_table([("Name", expert or BLANK), ("Son / daughter / spouse of", BLANK),
                        ("Residing / employed at", BLANK), ("Designation and qualification", BLANK)]),
              P("The expert states that the electronic record / output was obtained from the following device or record "
                "source (pre-filled from Part A; the expert must verify):", "h2"),
              PR(esc(_ticks(selected)), "cell"),
              kv_table([("Make and model", TODO), ("Serial number", TODO),
                        ("IMEI / UIN / UID / MAC / Cloud ID (as applicable)", TODO),
                        ("Other relevant information", "Hosts / systems: " + (", ".join(hosts) or "none") + ".")], widths=(62, 112)),
              P("Hash value(s) found by the expert", "h2"),
              P("The expert recomputes the hash of each record with an independent tool and writes the result in the last column.", "small")]
    if evidence:
        story.append(grid_table(
            ["No.", "Algorithm", "Hash stated in the ledger", "Hash recomputed by the expert"],
            [[str(i), hash_algorithm(str(g(e, 'payload_hash', ''))), mono(g(e, "payload_hash", "")), BLANK]
             for i, e in enumerate(evidence, start=1)], [9, 18, 77, 70]))
    story += [PR(f"{BOX} I recomputed every hash and each matches the value stated above.<br/>"
                 f"{BOX} I checked the integrity of the ledger chain myself (VAI's own check at draft time: "
                 f"{'PASSED' if view.integrity_ok else 'FAILED'}).", "body"),
              P("Hash report enclosed: Annexure 1 and the expert's own tool output.", "small"),
              kv_table([("(Name, designation and signature)", BLANK), ("Date (DD/MM/YYYY)", BLANK),
                        ("Time (IST), 24-hour format", BLANK + " hours"), ("Place", BLANK)], widths=(62, 112))]

    # ---------------- Annexures ----------------
    story += [P("Annexure 1 - Hash report (generated by VAI)", "h1"),
              kv_table([("Case", f"{case_id}"), ("Report generated", f"{fmt_utc(generated_at)} / {fmt_ist(generated_at)}"),
                        (view.root_label, view.root_value),
                        ("Ledger integrity", ("PASSED" if view.integrity_ok else "FAILED") + f" - {view.checked} entries checked")])]
    if view.entries:
        story.append(grid_table(["Seq", "Time (UTC)", "Kind", "Actor", "Payload hash", "Entry hash"],
                                [[str(g(e, "seq")), fmt_utc(g(e, "ts")), g(e, "kind", ""), g(e, "actor", ""),
                                  mono(g(e, "payload_hash", "")), mono(g(e, "hash", ""))] for e in view.entries],
                                [9, 28, 17, 20, 50, 50]))
    story += [P("Annexure 2 - Notes and open points for the reviewer", "h1"),
              bullet("This draft helps make the record verifiable. Whether a court accepts the record and the certificate "
                     "is for the court; this document makes no such claim."),
              bullet("Open point: confirm that the hash shown for each evidence item is the hash of the original file as "
                     "collected, and not of a description of the file."),
              bullet("Open point: who may act as the 'expert' in Part B. Sources reviewed say it is not always a Section 79A "
                     "Examiner of Electronic Evidence; the legal officer should confirm for this case."),
              bullet("Open point: the Schedule requires make, model, serial and device identifiers. These are not in the case "
                     "data and must come from the seizure / acquisition records."),
              bullet("Source of the form: Schedule to the Bharatiya Sakshya Adhiniyam, 2023, see section 63(4)(c) "
                     "(https://www.indiacode.nic.in/handle/123456789/20063)."),
              bullet("Names of persons in this draft are taken from the case record; demo names are fictional.")]

    return build_pdf(story, title=f"Draft Section 63 certificate {case_id}", author="Verifiable AI Investigator",
                     subject="Draft BSA 2023 section 63 certificate", watermark=WATERMARK,
                     footer=f"DRAFT s.63 BSA certificate - case {case_id} - not signed")

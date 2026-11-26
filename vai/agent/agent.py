"""Verifiable AI Investigator - the agent (package vai.agent).

What the agent promises
-----------------------
1. It first writes its PLAN to the ledger (plan + plan hash) BEFORE it does
   any work.
2. For each of the 6 planned steps it writes one "agent_step" entry BEFORE
   running the tool and one AFTER (or a "failed" entry if the tool crashes).
3. The conclusion is written to the ledger as a "conclusion" entry, with
   record IDs and limitations.
4. Nothing is final until an officer calls ``approve`` (also logged).

Rule mode (default) is fully deterministic.  LLM mode (only if LLM_API_KEY
is set) lets the LLM write only the plain summary; every fact comes from the
tools, and the model name, prompt hash and output hash are stored.
"""
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from vai.agent._bootstrap import ensure_contract

ensure_contract()

from vai.common.models import AgentStep, Case  # noqa: E402

from vai.agent.hashing import canonical_json, hash_obj, sha256_hex, to_jsonable  # noqa: E402
from vai.agent.llm import llm_from_env  # noqa: E402
from vai.agent.tools import AgentError, Tools, default_tools  # noqa: E402

ACTOR = "agent"

# The fixed investigation plan: (tool name, purpose in simple words).
PLAN_TEMPLATE: List[Tuple[str, str]] = [
    ("load_evidence", "Read the evidence files and turn them into events."),
    ("correlate", "Group related events into findings (ATT&CK technique)."),
    ("timeline", "Put the findings in time order."),
    ("map_law", "Suggest Indian law sections for each technique (officer confirms)."),
    ("conclude", "Write the conclusion with record IDs and limitations."),
    ("draft_report", "Prepare the DRAFT report (not final until officer approves)."),
]

CASE_LIMITATION = (
    "Analysis covers only the evidence files supplied; missing log sources could "
    "change the picture. Timestamps are used as given in the logs (UTC)."
)
CONFIDENCE_LIMITATION = {
    "high": "Logs show this activity, but logs alone do not prove WHO was behind the account.",
    "medium": "Partial pattern match; innocent explanations are not ruled out - manual check needed.",
    "low": "Weak indicator; treat it only as a lead, not as a conclusion.",
}
LEGAL_LIMITATION = (
    "suggested - officer confirms. Mapping is a suggestion for the officer, not legal advice."
)
FOOTER = (
    "Status: DRAFT, pending officer approval. Legal sections are "
    "'suggested - officer confirms'."
)

_BANNED_WORDS = ("admissible", "guilty", "convicted", "proven")


class Agent:
    """Investigation agent.

    Args:
        ledger: a ``vai.ledger.Ledger`` (needs ``append``, ``entries``, ``verify``).
        llm:    None  -> use LLM only if env LLM_API_KEY is set (else rule mode)
                False -> force rule mode
                object with ``name`` and ``complete(prompt)`` -> use it
        tools:  optional ``Tools`` (mocks for tests/demo). Default = real packages.
    """

    def __init__(self, ledger, llm=None, tools: Optional[Tools] = None) -> None:
        self.ledger = ledger
        self._tools = tools
        if llm is False:
            self.llm = None
        elif llm is None:
            self.llm = llm_from_env()
        else:
            self.llm = llm
        # In-memory copies of what was written, per case id, so that
        # completeness_report() can re-check them against the ledger.
        self._log: Dict[str, List[Tuple[int, str, dict]]] = {}
        self._conclusions: Dict[str, dict] = {}
        self._reports: Dict[str, bytes] = {}
        self._approvals: Dict[str, int] = {}

    # ------------------------------------------------------------------ basics
    @property
    def mode(self) -> str:
        return "llm" if self.llm else "rule"

    @property
    def tools(self) -> Tools:
        if self._tools is None:
            self._tools = default_tools()
        return self._tools

    def _write(self, case: Case, kind: str, payload: dict):
        entry = self.ledger.append(kind, ACTOR, payload)
        self._log.setdefault(case.id, []).append((entry.seq, kind, payload))
        return entry

    # -------------------------------------------------------------------- plan
    def plan(self, case: Case) -> List[dict]:
        """The planned steps. Pure function: writes nothing, same answer every time."""
        return [{"n": i, "tool": tool, "purpose": purpose}
                for i, (tool, purpose) in enumerate(PLAN_TEMPLATE, start=1)]

    # --------------------------------------------------------------------- run
    def run(self, case: Case, evidence_paths: Optional[List[str]] = None) -> Case:
        """Run the full investigation. Commits the plan to the ledger first."""
        case.findings, case.legal, case.steps, case.approved = [], [], [], False
        for store in (self._log, self._conclusions, self._reports, self._approvals):
            store.pop(case.id, None)

        plan = self.plan(case)
        plan_hash = hash_obj(plan)
        # 1) plan committed BEFORE any step runs
        if hasattr(self.ledger, "commit_plan"):  # contract v1.1: ledger's protocol is the source of truth
            e = self.ledger.commit_plan(plan, ACTOR)
            self._log.setdefault(case.id, []).append((e.seq, "agent_step", {
                "phase": "plan", "case_id": case.id, "mode": self.mode, "plan": plan, "plan_hash": plan_hash}))
        else:
            self._write(case, "agent_step", {
                "phase": "plan", "case_id": case.id, "mode": self.mode,
                "plan": plan, "plan_hash": plan_hash,
            })

        handlers: Dict[str, Tuple[Callable, Callable]] = {
            "load_evidence": (self._prep_load, self._exec_load),
            "correlate": (self._prep_correlate, self._exec_correlate),
            "timeline": (self._prep_timeline, self._exec_timeline),
            "map_law": (self._prep_law, self._exec_law),
            "conclude": (self._prep_conclude, self._exec_conclude),
            "draft_report": (self._prep_report, self._exec_report),
        }
        ctx = {"paths": evidence_paths, "plan_hash": plan_hash}
        for item in plan:
            self._run_step(case, item, handlers[item["tool"]], ctx)
        return case

    def _run_step(self, case: Case, item: dict, handler, ctx: dict) -> None:
        prepare, execute = handler
        n, tool = item["n"], item["tool"]
        base = {"case_id": case.id, "n": n, "tool": tool, "plan_hash": ctx["plan_hash"]}
        try:
            input_obj, reasoning, in_ids = prepare(case, ctx)
            input_hash = hash_obj(input_obj)
            base.update({"input_hash": input_hash, "reasoning": reasoning})
            if hasattr(self.ledger, "step_started"):
                e = self.ledger.step_started(n, tool, input_hash, ACTOR)
                self._log.setdefault(case.id, []).append((e.seq, "agent_step", {**base, "phase": "before", "record_ids": in_ids}))
            else:
                self._write(case, "agent_step", {**base, "phase": "before", "record_ids": in_ids})
            output_obj, out_ids = execute(case, ctx)
        except Exception as exc:  # log the failure too - nothing is hidden
            self._write(case, "agent_step", {
                **base, "phase": "failed", "record_ids": [],
                "error": f"{type(exc).__name__}: {exc}"})
            raise AgentError(f"step {n} ({tool}) failed: {exc}") from exc
        output_hash = hash_obj(output_obj)
        if hasattr(self.ledger, "step_finished"):
            e = self.ledger.step_finished(n, tool, output_hash, ACTOR, record_ids=out_ids, reasoning=reasoning)
            self._log.setdefault(case.id, []).append((e.seq, "agent_step", {
                **base, "phase": "after", "output_hash": output_hash, "record_ids": out_ids}))
        else:
            self._write(case, "agent_step", {
                **base, "phase": "after", "output_hash": output_hash, "record_ids": out_ids})
        case.steps.append(AgentStep(n=n, tool=tool, input_hash=input_hash,
                                    output_hash=output_hash, reasoning=reasoning,
                                    record_ids=out_ids))

    # ----------------------------------------------------------- step: evidence
    @staticmethod
    def _hash_paths(paths: List[str]) -> List[dict]:
        out = []
        for p in sorted(str(x) for x in paths):
            path = Path(p)
            files = sorted(path.rglob("*")) if path.is_dir() else [path]
            for f in files:
                if f.is_file():
                    out.append({"file": f.name, "sha256": sha256_hex(f.read_bytes())})
                elif not path.is_dir():
                    raise AgentError(f"evidence file not found: {p}")
        return out

    def _prep_load(self, case, ctx):
        if ctx["paths"]:
            input_obj = {"files": self._hash_paths(ctx["paths"])}
            reasoning = "Read every evidence file (fingerprinted by SHA-256) and convert to events."
        elif case.events:
            input_obj = {"events": to_jsonable(case.events)}
            reasoning = "Use the events already attached to the case; fingerprint them."
        else:
            raise AgentError("no evidence: give evidence_paths or events in the case")
        return input_obj, reasoning, []

    def _exec_load(self, case, ctx):
        if ctx["paths"]:
            case.events = list(self.tools.ingest(list(ctx["paths"])))
        return to_jsonable(case.events), [str(e.id) for e in case.events]

    # --------------------------------------------------------- step: correlate
    def _prep_correlate(self, case, ctx):
        return (to_jsonable(case.events),
                "Group events that show the same attacker technique into findings.",
                [str(e.id) for e in case.events])

    def _exec_correlate(self, case, ctx):
        case.findings = list(self.tools.correlate(case.events))
        return to_jsonable(case.findings), [str(f.id) for f in case.findings]

    # ---------------------------------------------------------- step: timeline
    def _prep_timeline(self, case, ctx):
        return (to_jsonable(case.findings),
                "Order the findings in time so the story reads start to end.",
                [str(f.id) for f in case.findings])

    def _exec_timeline(self, case, ctx):
        case.findings = list(self.tools.timeline(case.findings))
        return to_jsonable(case.findings), [str(f.id) for f in case.findings]

    # -------------------------------------------------------------- step: law
    @staticmethod
    def _techniques(case) -> List[str]:
        return sorted({f.technique_id for f in case.findings})

    def _prep_law(self, case, ctx):
        return ({"technique_ids": self._techniques(case)},
                "Look up suggested law sections for each technique; officer must confirm.",
                [str(f.id) for f in case.findings])

    def _exec_law(self, case, ctx):
        techs = self._techniques(case)
        case.legal = list(self.tools.map_techniques(techs)) if techs else []
        matched = {m.technique_id for m in case.legal}
        ids = [str(f.id) for f in case.findings if f.technique_id in matched]
        return to_jsonable(case.legal), ids

    # ---------------------------------------------------------- step: conclude
    def _facts(self, case) -> dict:
        return {
            "case_id": case.id, "title": case.title,
            "n_events": len(case.events),
            "hosts": sorted({str(e.host) for e in case.events}),
            "users": sorted({str(e.user) for e in case.events if e.user}),
            "ips": sorted({str(e.ip) for e in case.events if e.ip}),
            "findings": [{"id": str(f.id), "technique_id": f.technique_id, "title": f.title,
                          "confidence": f.confidence,
                          "event_ids": [str(i) for i in f.event_ids]} for f in case.findings],
            "legal": [{"technique_id": m.technique_id, "offence": m.offence, "act": m.act,
                       "section": m.section, "status": m.status} for m in case.legal],
        }

    def _prep_conclude(self, case, ctx):
        return ({"facts": self._facts(case), "mode": self.mode},
                "Write the conclusion only from tool outputs; list record IDs and limitations.",
                [str(f.id) for f in case.findings])

    @staticmethod
    def _rule_summary(facts: dict) -> str:
        parts = [f"Case {facts['case_id']} ({facts['title']}): {facts['n_events']} event(s) "
                 f"from {len(facts['hosts'])} host(s) were examined."]
        if not facts["findings"]:
            parts.append("No findings were produced from these events.")
        else:
            parts.append(f"{len(facts['findings'])} finding(s), in time order:")
            for i, f in enumerate(facts["findings"], start=1):
                parts.append(f"{i}) {f['technique_id']} - {f['title']} (confidence {f['confidence']}; "
                             f"events {', '.join(f['event_ids'])}).")
        if facts["legal"]:
            legal = "; ".join(f"{m['technique_id']} -> {m['act']} s.{m['section']} ({m['offence']})"
                              for m in facts["legal"])
            parts.append(f"Suggested legal mapping: {legal}.")
        return " ".join(parts)

    def _llm_summary(self, facts: dict) -> Tuple[Optional[str], dict]:
        """Ask the LLM for the summary only; reject it if it adds facts."""
        prompt = (
            "You are helping a police cyber cell. Write a plain summary (max 150 words) "
            "of the investigation below. Use ONLY the facts given. Do NOT add names, IP "
            "addresses, technique IDs or law sections that are not listed. Do not say "
            "anyone is guilty and do not say anything is admissible.\n\nFACTS:\n"
            + canonical_json(facts))
        meta = {"model": self.llm.name, "prompt_hash": sha256_hex(prompt),
                "output_hash": None, "accepted": False, "note": ""}
        try:
            text = self.llm.complete(prompt).strip()
        except Exception as exc:
            meta["note"] = f"LLM call failed ({type(exc).__name__}); rule summary used"
            return None, meta
        meta["output_hash"] = sha256_hex(text)
        allowed = canonical_json(facts)
        bad = [t for t in re.findall(r"T\d{4}(?:\.\d{3})?", text) if t not in allowed]
        bad += [ip for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text) if ip not in allowed]
        bad += [s for s in re.findall(r"[Ss]ection\s+(\d+[A-Za-z]?)", text) if s not in allowed]
        bad += [w for w in _BANNED_WORDS if w in text.lower()]
        if not text or bad:
            meta["note"] = f"LLM text rejected (not in tool facts or banned: {sorted(set(bad))}); rule summary used"
            return None, meta
        meta["accepted"] = True
        return text, meta

    def _exec_conclude(self, case, ctx):
        facts = self._facts(case)
        summary, llm_meta = None, None
        if self.llm:
            summary, llm_meta = self._llm_summary(facts)
        summary_mode = "llm" if summary else "rule"
        if summary is None:
            summary = self._rule_summary(facts)
        summary = f"{summary} {FOOTER}"

        finding_ids = [f["id"] for f in facts["findings"]]
        event_ids = sorted({i for f in facts["findings"] for i in f["event_ids"]})
        limitations = [CASE_LIMITATION] + sorted(
            {CONFIDENCE_LIMITATION[f["confidence"]] for f in facts["findings"]})
        if facts["legal"]:
            limitations.append(LEGAL_LIMITATION)
        payload = {
            "case_id": case.id, "summary": summary, "summary_mode": summary_mode,
            "finding_ids": finding_ids, "event_ids": event_ids,
            "limitations": limitations, "llm": llm_meta,
            "approval_status": "pending",
        }
        entry = self._write(case, "conclusion", payload)
        self._conclusions[case.id] = {"summary": summary, "hash": hash_obj(payload), "seq": entry.seq}
        return ({"summary": summary, "limitations": limitations},
                finding_ids + event_ids)

    # ------------------------------------------------------ step: draft report
    def _prep_report(self, case, ctx):
        body = {"id": case.id, "title": case.title, "events": to_jsonable(case.events),
                "findings": to_jsonable(case.findings), "legal": to_jsonable(case.legal)}
        return (body, "Prepare the DRAFT case report from the tool outputs. Not final.",
                [str(f.id) for f in case.findings])

    def _exec_report(self, case, ctx):
        pdf = self.tools.case_report_pdf(case, self.ledger)
        self._reports[case.id] = pdf
        report_hash = sha256_hex(pdf)
        self._write(case, "report", {"case_id": case.id, "status": "draft",
                                     "report_sha256": report_hash, "bytes": len(pdf)})
        return {"report_sha256": report_hash, "bytes": len(pdf)}, [str(f.id) for f in case.findings]

    # ---------------------------------------------------------------- results
    def summary(self, case: Case) -> Optional[str]:
        """The conclusion text written by the last run (None if not run)."""
        c = self._conclusions.get(case.id)
        return c["summary"] if c else None

    def report_bytes(self, case: Case) -> Optional[bytes]:
        """The DRAFT report bytes from the last run."""
        return self._reports.get(case.id)

    def status(self, case: Case) -> str:
        """not_run | pending_approval | approved"""
        if case.approved:
            return "approved"
        done = {s.tool for s in case.steps}
        return "pending_approval" if {"conclude", "draft_report"} <= done else "not_run"

    # ---------------------------------------------------------------- explain
    def explain(self, case: Case) -> List[dict]:
        """Why did the agent conclude this? Each item cites record IDs + a limitation."""
        if not case.steps:
            return []
        ev = {str(e.id): e for e in case.events}
        items: List[dict] = []
        for f in case.findings:
            eids = [str(i) for i in f.event_ids]
            evs = [ev[i] for i in eids if i in ev]
            users = sorted({str(e.user) for e in evs if e.user})
            hosts = sorted({str(e.host) for e in evs if e.host})
            ips = sorted({str(e.ip) for e in evs if e.ip})
            reason = (f"{f.technique_id} - {f.title}: supported by {len(eids)} event(s) "
                      f"(hosts: {', '.join(hosts) or 'n/a'}; users: {', '.join(users) or 'n/a'}; "
                      f"IPs: {', '.join(ips) or 'n/a'}). Confidence: {f.confidence}.")
            items.append({"reason": reason, "record_ids": [str(f.id)] + eids,
                          "limitation": CONFIDENCE_LIMITATION[f.confidence]})
        for m in case.legal:
            fids = [f for f in case.findings if f.technique_id == m.technique_id]
            ids = [str(f.id) for f in fids] + [str(i) for f in fids for i in f.event_ids]
            items.append({"reason": (f"Technique {m.technique_id} may relate to {m.act} "
                                     f"section {m.section} ({m.offence}). Status: {m.status}."),
                          "record_ids": ids, "limitation": LEGAL_LIMITATION})
        log = self._log.get(case.id, [])
        seqs = [f"ledger:{s}" for s, _k, p in log if p.get("phase") in ("plan", "before", "after")]
        step_ids = seqs or [f"step:{s.n}" for s in case.steps]
        items.append({"reason": (f"The agent followed a plan committed to the ledger before running; "
                                 f"{len(case.steps)} step(s) were each logged before and after."),
                      "record_ids": step_ids,
                      "limitation": ("This proves what the agent did, not that the source logs were "
                                     "complete or genuine. Run ledger verify() to check the record.")})
        state = self.status(case)
        items.append({"reason": ("Result is a DRAFT until an officer approves." if state != "approved"
                                 else "An officer approved this result; the approval is in the ledger."),
                      "record_ids": ([f"ledger:{self._approvals[case.id]}"]
                                     if case.id in self._approvals else []),
                      "limitation": CASE_LIMITATION})
        items.insert(0, {"reason": self._conclusions[case.id]["summary"]
                         if case.id in self._conclusions else "Conclusion text not in memory.",
                         "record_ids": [f"ledger:{self._conclusions[case.id]['seq']}"]
                         if case.id in self._conclusions else [],
                         "limitation": CASE_LIMITATION})
        return items

    # ---------------------------------------------------------------- approve
    def approve(self, case: Case, officer: str):
        """Officer approval. Logged to the ledger; refuses if ledger is broken."""
        if not officer or not str(officer).strip():
            raise ValueError("officer name is required")
        if self.status(case) == "not_run":
            raise AgentError("nothing to approve: run the case first")
        if case.approved:
            raise AgentError("case already approved")
        check = self.ledger.verify()
        if not check.ok:
            raise AgentError(f"ledger verification failed (broken at {check.broken_at}); not approving")
        if hasattr(self.ledger, "verify_completeness") and self._log.get(case.id):
            start = self._log[case.id][0][0]  # seq of this run's committed plan
            run_entries = [e for e in self.ledger.entries() if e.seq >= start and e.kind == "agent_step"]
            comp = self.ledger.verify_completeness(self.plan(case), run_entries)
            if not comp.ok:
                raise AgentError(f"completeness check failed ({getattr(comp, 'problems', comp.missing_steps)}); not approving")
        concl = self._conclusions.get(case.id, {})
        report = self._reports.get(case.id)
        entry = self._write(case, "approval", {
            "case_id": case.id, "officer": str(officer).strip(), "decision": "approved",
            "conclusion_hash": concl.get("hash"),
            "report_sha256": sha256_hex(report) if report is not None else None,
            "note": "Officer approval recorded. Legal sections remain 'suggested - officer confirms'.",
        })
        case.approved = True
        self._approvals[case.id] = entry.seq
        return entry

    # ------------------------------------------------------------ completeness
    def completeness_report(self, case: Case) -> dict:
        """Check that the run followed the committed plan and the ledger agrees.

        Checks: plan entry exists and its hash is right; every planned step has
        exactly one 'before' and one 'after' entry, in order, after the plan;
        no unplanned steps; every payload hash matches the ledger entry; the
        case's AgentSteps match the logged 'after' entries.
        """
        problems: List[str] = []
        log = self._log.get(case.id)
        if not log:
            return {"ok": False, "plan_hash": None, "planned_steps": 0, "logged_steps": 0,
                    "problems": ["no agent log in memory for this case"]}
        plans = [(s, p) for s, _k, p in log if p.get("phase") == "plan"]
        if len(plans) != 1:
            return {"ok": False, "plan_hash": None, "planned_steps": 0, "logged_steps": 0,
                    "problems": [f"expected 1 plan entry, found {len(plans)}"]}
        plan_seq, plan_payload = plans[0]
        plan, plan_hash = plan_payload["plan"], plan_payload["plan_hash"]
        if hash_obj(plan) != plan_hash:
            problems.append("plan hash does not match plan text")
        by_seq = {e.seq: e for e in self.ledger.entries()}
        for seq, kind, payload in log:
            e = by_seq.get(seq)
            if e is None:
                problems.append(f"ledger entry {seq} is missing")
            elif e.kind != kind or e.payload_hash != hash_obj(payload):
                problems.append(f"ledger entry {seq} does not match what the agent wrote")
        planned_n = {item["n"] for item in plan}
        for _s, _k, p in log:
            if p.get("phase") in ("before", "after", "failed") and p.get("n") not in planned_n:
                problems.append(f"unplanned step n={p.get('n')} found in log")
        logged = 0
        afters = {}
        for item in plan:
            n = item["n"]
            bef = [(s, p) for s, _k, p in log if p.get("phase") == "before" and p.get("n") == n]
            aft = [(s, p) for s, _k, p in log if p.get("phase") in ("after", "failed") and p.get("n") == n]
            if len(bef) != 1:
                problems.append(f"step {n}: expected 1 'before' entry, found {len(bef)}")
            if len(aft) != 1:
                problems.append(f"step {n}: expected 1 'after' entry, found {len(aft)}")
            if len(bef) == 1 and len(aft) == 1:
                (bs, bp), (as_, ap) = bef[0], aft[0]
                if not plan_seq < bs < as_:
                    problems.append(f"step {n}: entries are out of order")
                if bp["tool"] != item["tool"] or ap["tool"] != item["tool"]:
                    problems.append(f"step {n}: tool differs from plan")
                if bp.get("plan_hash") != plan_hash:
                    problems.append(f"step {n}: not linked to the committed plan")
                if ap["phase"] == "failed":
                    problems.append(f"step {n}: failed - {ap.get('error')}")
                else:
                    logged += 1
                    afters[n] = ap
        mine = {s.n: s for s in case.steps}
        for n, ap in afters.items():
            s = mine.get(n)
            if s is None or s.output_hash != ap["output_hash"] or s.input_hash != ap["input_hash"]:
                problems.append(f"step {n}: case.steps does not match the ledger log")
        return {"ok": not problems, "plan_hash": plan_hash, "planned_steps": len(plan),
                "logged_steps": logged, "problems": problems}

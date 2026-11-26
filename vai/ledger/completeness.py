"""Completeness check: did the agent do EXACTLY what it committed to do?

Protocol (written to the ledger as kind="agent_step" entries):
  1. plan   {"phase":"plan","plan_hash":..,"steps":[{"n","tool","input_hash"}]}
            written BEFORE the agent runs anything.
  2. before {"phase":"before","n":1,"tool":"..","input_hash":".."}   (before each tool run)
  3. after  {"phase":"after","n":1,"tool":"..","output_hash":"..","record_ids":[..],"reasoning":".."}

check_completeness() then finds: missing steps, unplanned/fake steps,
wrong order, a plan changed after commit, duplicates.
"""
from __future__ import annotations

from .hashing import canonical_json, sha256_hex


def _get(obj, key, default=None):
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


def normalize_step(step, index: int = 0) -> dict:
    n = _get(step, "n", index + 1)
    return {"n": int(n), "tool": str(_get(step, "tool", "") or ""),
            "input_hash": str(_get(step, "input_hash", "") or "")}


def normalize_plan(plan) -> list:
    return [normalize_step(s, i) for i, s in enumerate(plan)]


def plan_digest(plan) -> str:
    return sha256_hex(canonical_json(normalize_plan(plan)))


def check_completeness(plan, records):
    """Pure function. `records` = list of dicts {seq, kind, actor, payload(dict)}.

    Returns (problems, checked). Each problem is a dict
    {code, seq, step, detail}; `seq` is the ledger entry to look at (or None).
    """
    problems = []

    def add(code, detail, seq=None, step=None):
        problems.append({"code": code, "seq": seq, "step": step, "detail": detail})

    steps = normalize_plan(plan)
    planned, dup = {}, set()
    for s in steps:
        if s["n"] in planned:
            dup.add(s["n"])
        planned[s["n"]] = s
    for n in sorted(dup):
        add("PLAN_INVALID", f"step number {n} appears twice in the plan", step=n)

    recs = sorted((r for r in records if r.get("kind") == "agent_step"),
                  key=lambda r: r["seq"])
    plans, before, after, run = [], {}, {}, []
    for r in recs:
        p = r["payload"] if isinstance(r.get("payload"), dict) else {}
        phase = p.get("phase")
        if phase == "plan":
            plans.append(r)
        elif phase in ("before", "after"):
            run.append(r)
            (before if phase == "before" else after).setdefault(p.get("n"), []).append(r)
        else:
            add("UNKNOWN_PHASE", f"agent_step entry has unknown phase {phase!r}", seq=r["seq"])

    # ---- plan commitment ------------------------------------------------
    first_plan_seq = None
    if not plans:
        add("NO_PLAN_COMMIT", "no plan was committed to the ledger before the run")
    else:
        first_plan_seq = plans[0]["seq"]
        for extra in plans[1:]:
            add("MULTIPLE_PLAN_COMMITS", "a second plan was committed (plan may have been "
                "changed after the run started)", seq=extra["seq"])
        p0 = plans[0]["payload"]
        committed = p0.get("steps", [])
        try:
            committed_digest = plan_digest(committed)
        except (TypeError, ValueError, KeyError):
            committed_digest = None
        if committed_digest is None or committed_digest != p0.get("plan_hash"):
            add("PLAN_HASH_INVALID", "committed plan does not match its own plan_hash",
                seq=plans[0]["seq"])
        if committed_digest != plan_digest(steps):
            add("PLAN_MISMATCH", "the plan given for checking is different from the plan "
                "that was committed before the run", seq=plans[0]["seq"])
        for r in run:
            if r["seq"] < first_plan_seq:
                add("RUN_BEFORE_PLAN", "step logged before the plan was committed", seq=r["seq"],
                    step=r["payload"].get("n"))

    # ---- unplanned / fake entries --------------------------------------
    for r in run:
        p = r["payload"]
        n = p.get("n")
        if n not in planned:
            add("UNPLANNED_STEP", f"{p.get('phase')} entry for step {n} "
                f"(tool={p.get('tool')!r}) is not in the committed plan", seq=r["seq"], step=n)
            continue
        if p.get("tool") != planned[n]["tool"]:
            add("TOOL_MISMATCH", f"step {n} planned tool {planned[n]['tool']!r} but ledger "
                f"says {p.get('tool')!r}", seq=r["seq"], step=n)
        if (p.get("phase") == "before" and planned[n]["input_hash"]
                and p.get("input_hash") != planned[n]["input_hash"]):
            add("INPUT_MISMATCH", f"step {n} ran on a different input than planned",
                seq=r["seq"], step=n)
        if p.get("phase") == "after" and not p.get("output_hash"):
            add("EMPTY_OUTPUT", f"step {n} has an 'after' entry with no output_hash",
                seq=r["seq"], step=n)

    # ---- every planned step: exactly one before + one after, in order ---
    prev_end = 0
    for s in steps:
        n, tool = s["n"], s["tool"]
        b, a = before.get(n, []), after.get(n, [])
        if not b:
            add("MISSING_BEFORE", f"step {n} ({tool}): no 'before' entry (step not logged "
                "before running)", step=n, seq=a[0]["seq"] if a else None)
        if not a:
            add("MISSING_AFTER", f"step {n} ({tool}): no 'after' entry (result never logged)",
                step=n, seq=b[0]["seq"] if b else None)
        if len(b) > 1:
            add("DUPLICATE_BEFORE", f"step {n} ({tool}): {len(b)} 'before' entries", step=n,
                seq=b[1]["seq"])
        if len(a) > 1:
            add("DUPLICATE_AFTER", f"step {n} ({tool}): {len(a)} 'after' entries", step=n,
                seq=a[1]["seq"])
        if b and a:
            if b[0]["seq"] > a[0]["seq"]:
                add("ORDER", f"step {n} ({tool}): 'after' was logged before 'before'",
                    step=n, seq=a[0]["seq"])
            if b[0]["seq"] < prev_end:
                add("ORDER", f"step {n} ({tool}): started before the previous step finished "
                    "(or steps out of planned order)", step=n, seq=b[0]["seq"])
            prev_end = max(prev_end, a[0]["seq"])
    problems.sort(key=lambda p: (p["seq"] is None, p["seq"] or 0))
    return problems, len(recs)

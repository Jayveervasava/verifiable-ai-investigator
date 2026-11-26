"""Offline demo of the agent.   Run from the project folder:

    python -m vai.agent.demo            # uses MOCKS of the other packages
    python -m vai.agent.demo --real     # uses real vai.evidence/ledger/legal (after merge)

Everything is saved in results/agent/ .  Data is SYNTHETIC (FIR-1427/2027).
"""
import json
import sys
from pathlib import Path

from vai.agent import Agent, PLAN_TEMPLATE
from vai.agent._mocks.tools import MockLedger, mock_tools, write_demo_csv
from vai.common.models import Case

OUT = Path("results/agent")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    real = "--real" in argv
    OUT.mkdir(parents=True, exist_ok=True)
    evidence = write_demo_csv(OUT / "demo_input" / "fir1427_synthetic_events.csv")

    if real:
        from vai.ledger import Ledger
        ledger = Ledger(str(OUT / "demo_ledger.db"))
        agent = Agent(ledger, llm=False)
    else:
        ledger = MockLedger()
        agent = Agent(ledger, llm=False, tools=mock_tools())

    case = Case(id="FIR-1427/2027", title="Stolen credentials - r.mehta (synthetic demo)",
                victim="Acme Pvt Ltd (fictional)", officer="SI R. Patel (fictional)")
    agent.run(case, evidence_paths=[str(evidence)])
    audit = agent.completeness_report(case)
    verify = ledger.verify()
    before_approve = agent.status(case)
    agent.approve(case, "SI R. Patel (fictional)")

    result = {
        "mode": "real packages" if real else "mock packages",
        "agent_mode": agent.mode,
        "plan": agent.plan(case),
        "steps": [s.model_dump(mode="json") for s in case.steps],
        "summary": agent.summary(case),
        "explain": agent.explain(case),
        "completeness": audit,
        "ledger_verify": verify.model_dump(mode="json"),
        "status_before_approval": before_approve,
        "status_now": agent.status(case),
        "ledger_entries": [e.model_dump(mode="json") for e in ledger.entries()],
    }
    (OUT / "demo_run.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "config.json").write_text(json.dumps({
        "agent_mode": agent.mode, "plan": [t for t, _ in PLAN_TEMPLATE],
        "llm_enabled_by_env": agent.llm is not None}, indent=2), encoding="utf-8")
    (OUT / "demo_draft_report.pdf").write_bytes(agent.report_bytes(case) or b"")

    print("=== Verifiable AI Investigator - Agent demo ===")
    print(f"Mode: {result['mode']} | agent: {agent.mode} mode")
    print(f"Steps run: {len(case.steps)} / {len(PLAN_TEMPLATE)}")
    print(f"Ledger entries written: {len(ledger.entries())} | ledger verify ok: {verify.ok}")
    print(f"Plan followed (completeness): {audit['ok']}")
    print(f"Status before officer: {before_approve} -> after approve: {agent.status(case)}")
    print("Summary:", agent.summary(case))
    print(f"Saved results in: {OUT.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

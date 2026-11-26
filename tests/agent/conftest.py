"""Shared test setup for vai.agent tests (uses mocks of other packages)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from vai.agent import Agent  # noqa: E402  (also installs fallback contract if needed)
from vai.agent._mocks.tools import MockLedger, mock_tools, write_demo_csv  # noqa: E402
from vai.common.models import Case  # noqa: E402


@pytest.fixture(autouse=True)
def _no_llm_env(monkeypatch):
    """Tests run in rule mode unless a test says otherwise."""
    monkeypatch.delenv("LLM_API_KEY", raising=False)


@pytest.fixture
def evidence(tmp_path):
    return str(write_demo_csv(tmp_path / "fir1427_synthetic_events.csv"))


@pytest.fixture
def make_case():
    return lambda: Case(id="FIR-1427/2027", title="Stolen credentials (synthetic)",
                        victim="Acme (fictional)", officer="SI R. Patel (fictional)")


@pytest.fixture
def setup(evidence, make_case):
    """Returns (agent, ledger, case) AFTER a full rule-mode run."""
    ledger = MockLedger()
    agent = Agent(ledger, tools=mock_tools())
    case = make_case()
    agent.run(case, evidence_paths=[evidence])
    return agent, ledger, case

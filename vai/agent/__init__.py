"""vai.agent - the Verifiable AI Investigator agent (Claude 3)."""
from vai.agent._bootstrap import ensure_contract

ensure_contract()

from vai.agent.agent import Agent, PLAN_TEMPLATE  # noqa: E402
from vai.agent.tools import AgentError, Tools  # noqa: E402

__all__ = ["Agent", "AgentError", "Tools", "PLAN_TEMPLATE"]

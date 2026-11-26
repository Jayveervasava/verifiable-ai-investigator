"""The five outside functions the agent calls (from the CONTRACT).

Tests and the offline demo pass mock versions.  In the real system the
default tools come from vai.evidence and vai.legal.
"""
from dataclasses import dataclass
from typing import Callable


class AgentError(RuntimeError):
    """Raised when the agent cannot finish (the failure is also logged)."""


@dataclass
class Tools:
    ingest: Callable            # ingest(paths) -> [Event]
    correlate: Callable         # correlate(events) -> [Finding]
    timeline: Callable          # timeline(findings) -> [Finding]
    map_techniques: Callable    # map_techniques(ids) -> [LegalMatch]
    case_report_pdf: Callable   # case_report_pdf(case, ledger) -> bytes


def default_tools() -> Tools:
    """Load the real functions from the other packages (after merge)."""
    try:
        from vai.evidence import correlate, ingest, timeline
        from vai.legal import case_report_pdf, map_techniques
    except ImportError as exc:  # pragma: no cover - depends on the other packages
        raise AgentError(
            "vai.evidence / vai.legal not found. Pass Agent(..., tools=...) or use "
            "vai.agent._mocks.tools.mock_tools() until the packages are merged."
        ) from exc
    return Tools(ingest, correlate, timeline, map_techniques, case_report_pdf)

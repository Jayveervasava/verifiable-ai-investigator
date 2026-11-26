"""timeline(findings) -> [Finding] ordered as an attack story, plus a printable version."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from vai.common.models import Event, Finding

from . import common
from .common import event_dt
from .rules import CONF_ORDER, TACTIC_RANK

_FAR = datetime.max.replace(tzinfo=timezone.utc)
IST = timezone(timedelta(hours=5, minutes=30))


def _first_ts(f: Finding, ts: dict[str, datetime]) -> Optional[datetime]:
    times = [ts[i] for i in f.event_ids if i in ts]
    return min(times) if times else None


def timeline(findings: Iterable[Finding], events: Optional[Iterable[Event]] = None, *, min_confidence: str = "low") -> list[Finding]:
    """Order findings by the time of their first event (ties: kill-chain order, then id).

    CONTRACT is timeline(findings); Finding has no timestamp, so times come from the events seen by the
    latest correlate() call, or from the optional `events` argument.  Findings whose events are unknown
    are placed last in kill-chain order.  min_confidence filters out weaker findings ('low'|'medium'|'high').
    """
    ts = {e.id: event_dt(e) for e in events} if events is not None else common.EVENT_TS
    need = CONF_ORDER[min_confidence]
    keyed = []
    for f in findings:
        if CONF_ORDER[f.confidence] < need:
            continue
        t = _first_ts(f, ts)
        keyed.append((t is None, t or _FAR, TACTIC_RANK.get(f.technique_id, 99), f.id, f))
    keyed.sort(key=lambda k: k[:4])
    return [k[4] for k in keyed]


def timeline_text(findings: Iterable[Finding], events: Optional[Iterable[Event]] = None, *, min_confidence: str = "low") -> str:
    """Human-readable story, one line per finding, times in UTC and IST."""
    ts = {e.id: event_dt(e) for e in events} if events is not None else common.EVENT_TS
    lines = []
    for n, f in enumerate(timeline(findings, events, min_confidence=min_confidence), 1):
        t = _first_ts(f, ts)
        when = f"{t:%Y-%m-%d %H:%M:%S}Z / {t.astimezone(IST):%H:%M:%S} IST" if t else "time unknown"
        ids = ", ".join(f.event_ids[:6]) + (f" (+{len(f.event_ids) - 6} more)" if len(f.event_ids) > 6 else "")
        lines.append(f"{n:>2}. {when}  {f.technique_id:<9} [{f.confidence}]  {f.title}\n      records: {ids}")
    return "\n".join(lines)

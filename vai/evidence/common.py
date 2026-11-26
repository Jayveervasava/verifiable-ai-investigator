"""Shared helpers for vai.evidence: time, IP, user-name and action-string utilities.

Conventions used by every parser (so correlate() can rely on them):
  * Event.ts_utc  -> ISO-8601 UTC string with millisecond precision, e.g. 2027-03-14T15:42:07.123Z
  * Event.user    -> lower-case, domain stripped ("CORP\\R.Mehta" -> "r.mehta"); "" when unknown
  * Event.ip      -> clean IPv4/IPv6 text; "" when unknown / not an IP
  * Event.host    -> computer name (windows/linux) or AWS region (aws)
  * Event.action  -> "<name> | key=value | key=value ..."  (name comes first; free text such as a
                     command line comes last).  get_field()/action_name() read it back.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Optional

from vai.common.models import Event

UTC = timezone.utc

# --------------------------------------------------------------------------- time
_FRAC = re.compile(r"(\.\d{1,9})")
_SPACE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2} \d")


def parse_ts(value: Any) -> datetime:
    """Convert str / datetime / epoch seconds to a timezone-aware UTC datetime.

    Naive values are assumed to already be UTC.  Fractions longer than 6 digits
    (Windows writes 7) are truncated.  Raises ValueError on garbage.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC)
    else:
        s = str(value).strip()
        if not s:
            raise ValueError("empty timestamp")
        if _SPACE_DATE.match(s):
            s = s.replace(" ", "T", 1)
        if s[-1] in "Zz":
            s = s[:-1] + "+00:00"
        s = _FRAC.sub(lambda m: (m.group(1) + "000000")[:7], s, count=1)
        dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def iso_z(dt: datetime) -> str:
    """UTC datetime -> '2027-03-14T15:42:07.123Z'."""
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def event_dt(ev: Event) -> datetime:
    """Return an Event's timestamp as aware UTC datetime (works if the contract stores str or datetime)."""
    return parse_ts(ev.ts_utc)


# --------------------------------------------------------------------------- IP
# "Internal" = RFC1918 / loopback / link-local / CGNAT / IPv6 local.  We deliberately do NOT use
# ipaddress.is_private: it also flags the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) which our synthetic data uses as stand-ins for *public* addresses.
_INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fe80::/10", "fc00::/7",
    )
]
_NO_IP = {"", "-", "::", "0.0.0.0", "unknown", "n/a", "(null)"}


def clean_ip(value: Any) -> str:
    """Normalise an address string. Returns '' for '-', empty, hostnames and other non-IPs."""
    s = str(value or "").strip()
    if s.lower() in _NO_IP:
        return ""
    if s.lower().startswith("::ffff:"):
        s = s[7:]
    if s.count(":") == 1 and "." in s:          # 1.2.3.4:5555  -> 1.2.3.4
        s = s.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return ""


def is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _INTERNAL_NETS if n.version == addr.version)


def is_external_ip(ip: str) -> bool:
    return bool(ip) and not is_internal_ip(ip)


# --------------------------------------------------------------------------- user
def norm_user(value: Any) -> str:
    """'CORP\\R.Mehta' / 'r.mehta@corp.local' / 'R.Mehta' -> 'r.mehta'. '-' and empty -> ''."""
    s = str(value or "").strip()
    if s in ("", "-", "N/A", "(null)", "None"):
        return ""
    if "\\" in s:
        s = s.rsplit("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    return s.strip().lower()


# --------------------------------------------------------------------------- action string
def _clean_val(v: Any, limit: int = 400) -> str:
    s = str(v).replace("\r", " ").replace("\n", " ").strip()
    return s[:limit]


def build_action(name: str, **fields: Any) -> str:
    """'name | k=v | k=v' (empty values skipped; keep free-text fields like cmd= LAST)."""
    parts = [name]
    for k, v in fields.items():
        if v is None or str(v).strip() == "":
            continue
        parts.append(f"{k}={_clean_val(v)}")
    return " | ".join(parts)


def action_name(action: str) -> str:
    return action.split(" | ", 1)[0]


def get_field(action: str, key: str) -> str:
    """Read key=value back from an action string ('' when absent)."""
    m = re.search(rf"(?:^| \| ){re.escape(key)}=(.*?)(?= \| [a-z_]+=|$)", action)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------- Event factory
def make_event(
    id: str, dt: datetime, source: str, host: str, user: str, ip: str, action: str, raw_ref: str
) -> Event:
    return Event(
        id=id,
        ts_utc=iso_z(dt),
        source=source,
        host=(host or "").strip(),
        user=norm_user(user),
        ip=clean_ip(ip),
        action=action,
        raw_ref=raw_ref,
    )


# --------------------------------------------------------------------------- timeline registry
# correlate() remembers {event_id: datetime} so that timeline(findings) (whose contract signature has
# no events argument) can still sort findings chronologically.  Replaced on every correlate() call.
EVENT_TS: dict[str, datetime] = {}

"""Helpers to read Case / Ledger objects without depending on their exact class.

Works with pydantic models, dataclasses, SimpleNamespace and plain dicts, so
this package follows the CONTRACT but does not break if another package
changes its internal classes.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

IST = timezone(timedelta(hours=5, minutes=30), "IST")


def g(obj: Any, name: str, default: Any = None) -> Any:
    """Get field `name` from a dict or an object."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def as_list(value: Any) -> list:
    return list(value) if value else []


def parse_ts(value: Any) -> datetime | None:
    """Turn datetime / ISO string / unix number into an aware UTC datetime."""
    try:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        elif isinstance(value, str):
            text = value.strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
        else:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def fmt_utc(value: Any) -> str:
    dt = parse_ts(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else str(value)


def fmt_ist(value: Any) -> str:
    dt = parse_ts(value)
    return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST") if dt else ""


def sort_key_ts(value: Any) -> float:
    dt = parse_ts(value)
    return dt.timestamp() if dt else float("inf")


def short_hash(h: Any, n: int = 16) -> str:
    h = str(h or "")
    return h if len(h) <= n else h[:n] + "..."


def hash_algorithm(h: str) -> str:
    """Guess the hash algorithm from the hex length (the Schedule lists SHA1/SHA256/MD5/Other)."""
    h = (h or "").strip().lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        return "Other"
    return {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(h), "Other")


@dataclass
class LedgerView:
    """Everything the PDFs need to say about a ledger, with safe failure."""

    entries: list = field(default_factory=list)
    integrity_ok: bool = False
    integrity_error: str = ""
    checked: int = 0
    broken_at: Any = None
    completeness: str = "not_checked"  # ok | failed | not_checked | error
    missing_steps: list = field(default_factory=list)
    completeness_error: str = ""
    root_label: str = ""
    root_value: str = ""
    kinds: Counter = field(default_factory=Counter)

    def of_kind(self, kind: str) -> list:
        return [e for e in self.entries if str(g(e, "kind")) == kind]


def collect_ledger(ledger: Any, plan: Any = None) -> LedgerView:
    """Ask the ledger for entries, integrity and completeness. Never claims OK on error."""
    view = LedgerView()
    try:
        raw = g(ledger, "entries")
        view.entries = list(raw() if callable(raw) else (raw or []))
    except Exception as exc:  # noqa: BLE001
        view.integrity_error = f"could not read ledger entries: {exc}"
    view.kinds = Counter(str(g(e, "kind")) for e in view.entries)

    try:
        res = ledger.verify()
        view.integrity_ok = bool(g(res, "ok", False))
        view.checked = int(g(res, "checked", 0) or 0)
        view.broken_at = g(res, "broken_at")
    except Exception as exc:  # noqa: BLE001
        view.integrity_ok = False
        view.integrity_error = view.integrity_error or f"verification could not run: {exc}"

    if plan is None:
        view.completeness = "not_checked"
    else:
        try:
            res = ledger.verify_completeness(plan, view.entries)
            view.missing_steps = as_list(g(res, "missing_steps"))
            view.completeness = "ok" if bool(g(res, "ok", False)) else "failed"
        except Exception as exc:  # noqa: BLE001
            view.completeness = "error"
            view.completeness_error = str(exc)

    view.root_label, view.root_value = _root(ledger, view.entries)
    return view


def _root(ledger: Any, entries: list) -> tuple[str, str]:
    if not entries:
        return "Ledger root", "(ledger is empty)"
    for name in ("merkle_root", "root"):
        fn = getattr(ledger, name, None)
        if callable(fn):
            try:
                val = fn()
                if val:
                    return "Merkle root", str(val)
            except Exception:  # noqa: BLE001
                pass
    try:
        proof = ledger.merkle_proof(g(entries[-1], "seq"))
        val = g(proof, "root")
        if val:
            return "Merkle root", str(val)
    except Exception:  # noqa: BLE001
        pass
    return "Chain head hash (hash of last entry; Merkle root not available)", str(g(entries[-1], "hash", ""))

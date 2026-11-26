"""Compatibility layer.

The real data models live in vai/common/models.py (owned by Claude 0, pydantic v2).
If that module can be imported we use its LegalMatch; otherwise a tiny dataclass
with the same fields is used so this package can still run and be tested alone.
"""
from __future__ import annotations

from dataclasses import dataclass

STATUS_TEXT = "suggested - officer confirms"

try:  # pragma: no cover - depends on the full repo being present
    from vai.common.models import LegalMatch  # type: ignore
except Exception:  # noqa: BLE001 - any import problem means "use fallback"

    @dataclass
    class LegalMatch:  # type: ignore[no-redef]
        """Fallback with the exact contract fields."""

        technique_id: str
        offence: str
        act: str
        section: str
        reason: str
        source_url: str
        status: str = STATUS_TEXT

"""Optional shared helper: one canonical way to hash payloads.

Not part of the frozen contract, but recommended so that every package
produces identical hashes for identical data.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    """Stable JSON: sorted keys, no spaces, UTF-8. Pydantic models are dumped first."""
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_payload(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

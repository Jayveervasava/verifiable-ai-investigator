"""Canonical hashing helpers.

IMPORTANT (for the ledger owner): every payload the agent writes to the
ledger can be re-hashed with ``hash_obj(payload)``.  That is:

    sha256( json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8") )
"""
import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """Same data -> same text, always (sorted keys, no extra spaces)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data) -> str:
    """SHA-256 of text (utf-8) or bytes, as a hex string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    """Hash any JSON-like object (after converting pydantic models)."""
    return sha256_hex(canonical_json(to_jsonable(obj)))


def to_jsonable(obj: Any) -> Any:
    """Turn pydantic models (and lists/dicts of them) into plain JSON data."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    return obj

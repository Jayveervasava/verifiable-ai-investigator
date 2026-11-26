"""Hash helpers. The ONLY place where hash formulas are defined.

payload_hash = SHA-256( canonical JSON of payload )
hash         = SHA-256( prev_hash | payload_hash | seq | ts | kind | actor )
hmac         = HMAC-SHA256( LEDGER_HMAC_KEY, hash )

Note: a "|" separator is put between the fields of `hash` so that two
different entries can never produce the same text to hash.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, is_dataclass

GENESIS_HASH = "0" * 64
HASH_ALGORITHM = "sha256"


def _default(obj):
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    raise TypeError(
        f"{type(obj).__name__} cannot be written to the ledger; convert it to "
        "str/int/float/bool/None/list/dict first (datetimes -> ISO string)."
    )


def canonical_json(obj) -> str:
    """Deterministic JSON: sorted keys, no spaces, UTF-8, no NaN."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False, default=_default)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_hash(payload) -> str:
    return sha256_hex(canonical_json(payload))


def compute_entry_hash(prev_hash: str, payload_hash_: str, seq: int, ts: str,
                       kind: str, actor: str) -> str:
    return sha256_hex("|".join([prev_hash, payload_hash_, str(seq), ts, kind, actor]))


def compute_hmac(key: bytes, entry_hash: str) -> str:
    return hmac.new(key, entry_hash.encode("ascii"), hashlib.sha256).hexdigest()


def compute_head_hmac(key: bytes, seq: int, entry_hash: str) -> str:
    return hmac.new(key, f"HEAD|{seq}|{entry_hash}".encode("ascii"),
                    hashlib.sha256).hexdigest()

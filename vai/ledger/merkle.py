"""Merkle tree over ledger entry hashes (leaf = entry `hash`).

leaf = SHA-256(0x00 || entry_hash_bytes)
node = SHA-256(0x01 || left || right)
A node with no right sibling is carried up unchanged (no duplication).
"""
from __future__ import annotations

import hashlib

from .hashing import compute_entry_hash

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _leaf(entry_hash_hex: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(entry_hash_hex)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _path_sides(index: int, size: int):
    """Which side each sibling sits on, for leaf `index` in a tree of `size`."""
    sides, n, i = [], size, index
    while n > 1:
        if i % 2 == 0:
            if i + 1 < n:
                sides.append("right")
        else:
            sides.append("left")
        i //= 2
        n = (n + 1) // 2
    return sides


class MerkleTree:
    def __init__(self, entry_hashes_hex):
        level = [_leaf(h) for h in entry_hashes_hex]
        self.size = len(level)
        self.levels = [level]
        while len(level) > 1:
            nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
            if len(level) % 2:
                nxt.append(level[-1])
            self.levels.append(nxt)
            level = nxt

    @property
    def root(self) -> str:
        return self.levels[-1][0].hex() if self.size else EMPTY_ROOT

    def path(self, index: int):
        if not 0 <= index < self.size:
            raise IndexError(index)
        out, i = [], index
        for level in self.levels[:-1]:
            if i % 2 == 0:
                if i + 1 < len(level):
                    out.append({"side": "right", "hash": level[i + 1].hex()})
            else:
                out.append({"side": "left", "hash": level[i - 1].hex()})
            i //= 2
        return out


def verify_proof(proof, trusted_root=None) -> bool:
    """Check a proof produced by Ledger.merkle_proof().

    Checks: (1) entry fields really give entry.hash, (2) the path leads to
    proof["root"], (3) the path shape matches the claimed position, and
    (4) if `trusted_root` is given, the root equals it. Without a trusted root
    this only proves the proof is internally consistent - always compare the
    root with one you got from a trusted place (e.g. the printed report).
    """
    try:
        e = proof["entry"]
        seq, size = int(e["seq"]), int(proof["tree_size"])
        if not 1 <= seq <= size:
            return False
        if compute_entry_hash(e["prev_hash"], e["payload_hash"], seq, e["ts"],
                              e["kind"], e["actor"]) != e["hash"]:
            return False
        path = proof["path"]
        if [s["side"] for s in path] != _path_sides(seq - 1, size):
            return False
        cur = _leaf(e["hash"])
        for step in path:
            sib = bytes.fromhex(step["hash"])
            cur = _node(cur, sib) if step["side"] == "right" else _node(sib, cur)
        root = cur.hex()
        if root != proof["root"]:
            return False
        if trusted_root is not None and root != trusted_root:
            return False
        return True
    except (KeyError, TypeError, ValueError, AttributeError):
        return False

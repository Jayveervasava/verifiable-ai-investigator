"""vai.ledger - tamper-evident, hash-chained ledger (Claude 2)."""
from .completeness import check_completeness, normalize_plan, plan_digest
from .core import KINDS, Ledger, LedgerError, LedgerTamperedError
from .export import export_package
from .hashing import GENESIS_HASH, canonical_json, payload_hash
from .merkle import EMPTY_ROOT, MerkleTree, verify_proof
from .tamper import copy_db, tamper_demo

__all__ = ["Ledger", "LedgerError", "LedgerTamperedError", "KINDS", "verify_proof",
           "MerkleTree", "EMPTY_ROOT", "tamper_demo", "copy_db", "export_package",
           "check_completeness", "plan_digest", "normalize_plan", "canonical_json",
           "payload_hash", "GENESIS_HASH"]
__version__ = "1.0.0"

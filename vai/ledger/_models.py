"""Single place where this package imports the shared contract models."""
try:
    from vai.common.models import LedgerEntry, VerifyResult  # real contract
except ImportError:  # contract file not merged yet -> use identical mock
    from ._models_mock import LedgerEntry, VerifyResult  # noqa: F401


def make_verify_result(ok, checked, broken_at=None, missing_texts=(), missing_steps=()):
    """Build a VerifyResult.

    `missing_steps` in the contract is a list; we put readable strings in it.
    If the real contract turns out to want integers, we fall back to step
    numbers so integration never crashes.
    """
    try:
        return VerifyResult(ok=ok, checked=checked, broken_at=broken_at,
                            missing_steps=list(missing_texts))
    except Exception:
        nums = sorted({int(n) for n in missing_steps if n is not None})
        return VerifyResult(ok=ok, checked=checked, broken_at=broken_at,
                            missing_steps=nums)

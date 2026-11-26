"""Single place where this package imports the shared contract models."""
try:
    from vai.common.models import LedgerEntry, VerifyResult  # real contract
except ImportError:  # contract file not merged yet -> use identical mock
    from ._models_mock import LedgerEntry, VerifyResult  # noqa: F401


def make_verify_result(ok, checked, broken_at=None, missing_texts=(), missing_steps=()):
    """Contract v1.1: step numbers in `missing_steps`, readable reasons in `problems`."""
    nums = sorted({int(n) for n in missing_steps if n is not None})
    try:
        return VerifyResult(ok=ok, checked=checked, broken_at=broken_at,
                            missing_steps=nums, problems=list(missing_texts))
    except Exception:  # older contract without `problems`
        return VerifyResult(ok=ok, checked=checked, broken_at=broken_at, missing_steps=nums)

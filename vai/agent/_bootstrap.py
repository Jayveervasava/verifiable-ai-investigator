"""Fallback for the shared contract models.

The real contract lives in ``vai/common/models.py`` (owned by Claude 0).
When this package is used on its own (before it is merged into the main
repo) that file may not exist.  In that case we register a local copy of the
contract so that ``from vai.common.models import ...`` still works.

When the real file exists this function does nothing.
"""
import sys
import types


def ensure_contract() -> bool:
    """Return True if the fallback copy had to be used, else False."""
    try:
        import vai.common.models  # noqa: F401
        return False
    except ImportError:
        pass
    from vai.agent._mocks import contract_models

    common = types.ModuleType("vai.common")
    common.__path__ = []  # marks it as a package
    common.models = contract_models
    sys.modules["vai.common"] = common
    sys.modules["vai.common.models"] = contract_models
    return True

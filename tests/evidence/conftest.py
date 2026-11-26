"""pytest bootstrap: if the real contract (vai/common/models.py from Claude 0) is not importable yet,
fall back to the DEV-ONLY mock shipped in dev_mock/.  Once Claude 0 merges the real file this does nothing."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
try:
    import vai.common.models  # noqa: F401
except ModuleNotFoundError:
    sys.path.insert(0, str(ROOT / "dev_mock"))

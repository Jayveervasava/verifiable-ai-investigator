"""Download the REAL public sample logs onto YOUR computer (needs internet + git).

    python -m vai.evidence.tools.fetch_public_samples            # clones into data/sample/case_public/raw/
    pip install python-evtx                                       # only needed to read .evtx
    python - <<'PY'
    from vai.evidence import ingest, correlate
    ev = ingest("data/sample/case_public/raw/EVTX-ATTACK-SAMPLES")   # reads every .evtx
    for f in correlate(ev): print(f.technique_id, f.confidence, f.title)
    PY

The raw files are NOT included in our zip (licence / size).  Check each repository's licence before redistributing.
Stratus Red Team ships no logs: install it, detonate a technique in a throw-away AWS lab account,
then export the account's CloudTrail JSON and ingest that file.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPOS = {"EVTX-ATTACK-SAMPLES": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES"}


def main() -> None:
    dest = Path("data/sample/case_public/raw")
    dest.mkdir(parents=True, exist_ok=True)
    for name, url in REPOS.items():
        target = dest / name
        if target.exists():
            print(f"already there, not touching: {target}")
            continue
        print(f"cloning {url} -> {target}")
        r = subprocess.run(["git", "clone", "--depth", "1", url, str(target)])
        if r.returncode:
            sys.exit("git clone failed - check internet / git installation")
    print("done. Next: pip install python-evtx, then ingest(...) the .evtx files.")


if __name__ == "__main__":
    main()

"""ingest(paths) -> [Event]  (plus ingest_with_report() and hash_files() for chain-of-custody).

ID scheme (deterministic for the same files in the same order):
  W-<EventRecordID>   windows   (suffix -2, -3 .. if two hosts reuse the same record id)
  L-<n>               linux     n = physical line number, continued across files (file 2 starts after file 1)
  A-<n>               aws       n = record index, continued across files
raw_ref = '<file name>#line=<n>' | '#index=<n>' | '#record=<n>'  -> points back to the original record.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Iterable, Optional, Union

from vai.common.models import Event

from . import parse_aws, parse_linux, parse_windows
from .common import event_dt
from .parse_windows import _open_text

PathLike = Union[str, os.PathLike]
_KNOWN_EXT = {".evtx", ".json", ".jsonl", ".log", ".txt", ".gz"}


def sha256_file(path: PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths: Union[PathLike, Iterable[PathLike]]) -> dict[str, str]:
    """SHA-256 of every evidence file (for the ledger / BSA Section 63 certificate)."""
    return {str(p): sha256_file(p) for p in _expand(paths)}


def _expand(paths: Union[PathLike, Iterable[PathLike]]) -> list[Path]:
    if isinstance(paths, (str, os.PathLike)):
        paths = [paths]
    out: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and not f.name.startswith(("_", ".")) and f.suffix.lower() in _KNOWN_EXT:
                    out.append(f)
        elif p.is_file():
            out.append(p)
        else:
            raise FileNotFoundError(f"evidence path not found: {p}")
    return out


def _detect_kind(path: Path) -> Optional[str]:
    name = path.name.lower()
    if name.endswith(".evtx"):
        return "windows_evtx"
    base = name[:-3] if name.endswith(".gz") else name
    if base.endswith((".log", ".txt")):
        return "linux"
    if base.endswith((".json", ".jsonl")):
        with _open_text(str(path)) as fh:
            head = fh.read(4000)
        if '"Records"' in head or '"eventName"' in head or '"eventSource"' in head:
            return "aws"
        if '"EventID"' in head or '"Event"' in head or '"event_record_id"' in head:
            return "windows_json"
    return None


def ingest_with_report(
    paths: Union[PathLike, Iterable[PathLike]], *, year: Optional[int] = None, log_tz: str = "UTC"
) -> tuple[list[Event], dict[str, Any]]:
    """Parse evidence files.  year / log_tz only matter for classic syslog lines ('Mar 14 09:12:01')
    that carry no year or timezone.  Returns (events sorted by time, report dict)."""
    files = _expand(paths)
    events: list[Event] = []
    seen_ids: set[str] = set()
    report: dict[str, Any] = {"files": [], "total_events": 0, "total_errors": 0, "total_unclassified": 0}
    l_offset = a_offset = 0

    def uniq(i: str) -> str:
        if i not in seen_ids:
            seen_ids.add(i)
            return i
        n = 2
        while f"{i}-{n}" in seen_ids:
            n += 1
        seen_ids.add(f"{i}-{n}")
        return f"{i}-{n}"

    for f in files:
        kind = _detect_kind(f)
        info: dict[str, Any] = {"path": str(f), "name": f.name, "bytes": f.stat().st_size, "sha256": sha256_file(f),
                                "kind": kind, "events": 0, "unclassified": 0, "errors": 0, "error_samples": []}
        report["files"].append(info)
        if kind is None:
            info["note"] = "skipped: format not recognised"
            continue

        def err(msg: str) -> None:
            info["errors"] += 1
            if len(info["error_samples"]) < 5:
                info["error_samples"].append(msg)

        if kind in ("windows_json", "windows_evtx"):
            it = parse_windows.iter_evtx(str(f)) if kind == "windows_evtx" else parse_windows.iter_json_records(str(f))
            for n, (flat, loc, e) in enumerate(it, 1):
                if e:
                    err(e)
                    continue
                if flat is None:
                    err(f"{loc}: not a Windows event record")
                    continue
                try:
                    rid = flat.get("RecordID") or (info["events"] + 1)
                    ev, ok = parse_windows.event_from_flat(flat, uniq(f"W-{rid}"), f"{f.name}#{loc}")
                except Exception as ex:                      # bad timestamp etc. -> counted, never crashes
                    err(f"{loc}: {type(ex).__name__}: {ex}")
                    continue
                events.append(ev)
                info["events"] += 1
                info["unclassified"] += 0 if ok else 1
        elif kind == "linux":
            y = year or int(os.environ.get("VAI_LOG_YEAR", 0)) or _mtime_year(f)
            nlines = 0
            with _open_text(str(f)) as fh:
                for n, line in enumerate(fh, 1):
                    nlines = n
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    try:
                        ev, ok = parse_linux.event_from_line(line, uniq(f"L-{l_offset + n}"), f"{f.name}#line={n}", y, log_tz)
                    except Exception as ex:
                        err(f"line {n}: {type(ex).__name__}: {ex}")
                        continue
                    if ev is None:
                        err(f"line {n}: not a syslog line")
                        seen_ids.discard(f"L-{l_offset + n}")
                        continue
                    events.append(ev)
                    info["events"] += 1
                    info["unclassified"] += 0 if ok else 1
            l_offset += nlines
        else:  # aws
            count = 0
            for rec, loc, e in parse_aws.iter_cloudtrail(str(f)):
                count += 1
                if e:
                    err(e)
                    continue
                try:
                    idx = a_offset + int(loc.split("=")[1])
                    events.append(parse_aws.event_from_record(rec, uniq(f"A-{idx}"), f"{f.name}#{loc}"))
                except Exception as ex:
                    err(f"{loc}: {type(ex).__name__}: {ex}")
                    continue
                info["events"] += 1
            a_offset += count
        report["total_events"] += info["events"]
        report["total_errors"] += info["errors"]
        report["total_unclassified"] += info["unclassified"]
    events.sort(key=lambda e: (event_dt(e), e.id))
    return events, report


def ingest(paths: Union[PathLike, Iterable[PathLike]], *, year: Optional[int] = None, log_tz: str = "UTC") -> list[Event]:
    """CONTRACT: ingest(paths) -> [Event]  (sorted by time).  Use ingest_with_report() to also get counts/hashes."""
    return ingest_with_report(paths, year=year, log_tz=log_tz)[0]


def _mtime_year(path: Path) -> int:
    from datetime import datetime
    return datetime.fromtimestamp(path.stat().st_mtime).year

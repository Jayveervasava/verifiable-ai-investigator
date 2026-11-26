"""MITRE ATT&CK technique -> Indian law mapping.

Data is in data/mitre_to_law.yaml (researched, with doubts). Every result is
"suggested - officer confirms"; nothing here decides guilt.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import yaml

from ._compat import STATUS_TEXT, LegalMatch

DATA_FILE = Path(__file__).parent / "data" / "mitre_to_law.yaml"
REQUIRED_TECHNIQUES = (
    "T1078", "T1021", "T1530", "T1110", "T1566",
    "T1486", "T1048", "T1059", "T1098", "T1005",
)
ALLOWED_ACTS = ("IT Act 2000", "BNS 2023")
ENTRY_FIELDS = ("offence", "act", "section", "reason", "source_url")


@lru_cache(maxsize=1)
def load_mapping(path: str | None = None) -> dict:
    with open(path or DATA_FILE, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def mapping_sha256() -> str:
    return hashlib.sha256(DATA_FILE.read_bytes()).hexdigest()


def validate_mapping(data: dict) -> list[str]:
    """Return a list of problems (empty list = file is fine)."""
    problems: list[str] = []
    techniques = (data or {}).get("techniques") or {}
    for tid in REQUIRED_TECHNIQUES:
        if tid not in techniques:
            problems.append(f"{tid}: technique missing")
    for tid, block in techniques.items():
        entries = (block or {}).get("entries") or []
        if not entries:
            problems.append(f"{tid}: no entries")
        for i, e in enumerate(entries):
            for f in ENTRY_FIELDS:
                if not str(e.get(f) or "").strip():
                    problems.append(f"{tid}[{i}]: field '{f}' is empty")
            if e.get("act") not in ALLOWED_ACTS:
                problems.append(f"{tid}[{i}]: act must be one of {ALLOWED_ACTS}")
            if not str(e.get("source_url") or "").startswith("https://www.indiacode.nic.in/"):
                problems.append(f"{tid}[{i}]: source_url must be an indiacode.nic.in link")
    return problems


def normalize_id(technique_id: str) -> str:
    """'t1078.004' -> 'T1078' (sub-techniques use the parent technique's mapping)."""
    return str(technique_id).strip().upper().split(".")[0]


def technique_name(technique_id: str) -> str:
    block = load_mapping()["techniques"].get(normalize_id(technique_id))
    return (block or {}).get("name", "")


def map_techniques(ids: Iterable[str]) -> list[LegalMatch]:
    """Contract function: technique ids -> list of LegalMatch (suggestions only)."""
    techniques = load_mapping()["techniques"]
    out: list[LegalMatch] = []
    seen: set[str] = set()
    for raw in ids or []:
        base = normalize_id(raw)
        if base in seen or base not in techniques:
            continue
        seen.add(base)
        for e in techniques[base]["entries"]:
            out.append(
                LegalMatch(
                    technique_id=base,
                    offence=e["offence"],
                    act=e["act"],
                    section=str(e["section"]),
                    reason=e["reason"],
                    source_url=e["source_url"],
                    status=STATUS_TEXT,
                )
            )
    return out


def unmapped(ids: Iterable[str]) -> list[str]:
    techniques = load_mapping()["techniques"]
    result: list[str] = []
    for raw in ids or []:
        base = normalize_id(raw)
        if base not in techniques and base not in result:
            result.append(base)
    return result


def doubt_for(technique_id: str, act: str, section: str) -> str:
    """Doubt text of one mapping entry ('' if none)."""
    block = load_mapping()["techniques"].get(normalize_id(technique_id)) or {}
    for e in block.get("entries", []):
        if e["act"] == act and str(e["section"]) == str(section):
            return e.get("doubt") or ""
    return ""


def global_doubts() -> list[str]:
    return list(load_mapping()["meta"].get("global_doubts", []))

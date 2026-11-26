"""Windows event parser: EVTX (optional python-evtx), evtx_dump-style JSON/JSONL, flat JSON, XML.

Each record becomes ONE Event.  Unknown EventIDs are kept as 'windows_event_<id>' (nothing is
silently dropped) and counted as 'unclassified' in the ingest report.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Iterator, Optional

from vai.common.models import Event

from .common import build_action, make_event, parse_ts

SECURITY_NAMES = {
    4624: "logon_success", 4625: "logon_failed", 4634: "logoff", 4648: "explicit_credential_logon",
    4672: "special_privileges_assigned", 4688: "process_create", 4697: "service_installed",
    7045: "service_installed", 4698: "scheduled_task_created", 4720: "account_created",
    4732: "group_member_added", 1102: "audit_log_cleared", 104: "audit_log_cleared",
    4768: "kerberos_tgt_request", 4769: "kerberos_service_ticket",
    4776: "ntlm_credential_validation", 5140: "share_access",
}
SYSMON_NAMES = {1: "process_create", 3: "network_connection", 10: "process_access", 11: "file_create"}


def _txt(v: Any) -> Any:
    if isinstance(v, dict):
        return v.get("#text", v.get("text", ""))
    return v


def _to_int(v: Any) -> Optional[int]:
    try:
        return int(str(_txt(v)).strip())
    except (ValueError, TypeError):
        return None


def _name_attr(d: Any) -> str:
    if isinstance(d, dict):
        a = d.get("#attributes") or {}
        return a.get("Name") or d.get("@Name") or d.get("Name") or ""
    return ""


def flatten_windows(obj: dict) -> Optional[dict]:
    """Normalise a record (evtx_dump / flat JSON) to a flat dict with
    EventID, RecordID, Time, Computer, Channel, Provider + all EventData fields.  None if not a Windows event."""
    wrapper = {}
    if isinstance(obj.get("data"), dict) and "Event" in obj["data"]:      # evtx_dump jsonl wrapper
        wrapper, obj = obj, obj["data"]
    ev = obj.get("Event")
    if isinstance(ev, dict):
        sysd = ev.get("System") or {}
        data = ev.get("EventData") or ev.get("UserData") or {}
        flat: dict[str, Any] = {}
        if isinstance(data, dict):
            if isinstance(data.get("Data"), list):                          # older converter style
                for item in data["Data"]:
                    if isinstance(item, dict):
                        flat[_name_attr(item)] = _txt(item)
            else:
                flat.update({k: _txt(v) for k, v in data.items()})
        tc = sysd.get("TimeCreated")
        if isinstance(tc, dict):
            t = (tc.get("#attributes") or {}).get("SystemTime") or tc.get("@SystemTime") or tc.get("SystemTime")
        else:
            t = tc
        flat.update(
            EventID=_to_int(sysd.get("EventID")),
            RecordID=_to_int(sysd.get("EventRecordID")) or wrapper.get("event_record_id"),
            Time=t or wrapper.get("timestamp"),
            Computer=_txt(sysd.get("Computer")) or "",
            Channel=_txt(sysd.get("Channel")) or "",
            Provider=_name_attr(sysd.get("Provider")) if isinstance(sysd.get("Provider"), dict) else (sysd.get("Provider") or ""),
        )
        return flat if flat["EventID"] is not None else None
    if "EventID" in obj:                                                     # already flat
        flat = dict(obj)
        flat["EventID"] = _to_int(obj["EventID"])
        flat["RecordID"] = _to_int(obj.get("EventRecordID") or obj.get("RecordID"))
        flat["Time"] = obj.get("TimeCreated") or obj.get("Time") or obj.get("@timestamp") or obj.get("UtcTime")
        flat["Computer"] = obj.get("Computer") or obj.get("Hostname") or ""
        flat.setdefault("Channel", "")
        flat.setdefault("Provider", "")
        return flat if flat["EventID"] is not None else None
    return None


def flat_from_xml(xml_text: str) -> dict:
    """Parse one <Event> XML (as produced by python-evtx record.xml()) into the flat dict."""
    low = xml_text.lower()
    if "<!doctype" in low or "<!entity" in low:      # refuse entity-expansion tricks in untrusted evidence
        raise ValueError("XML with DOCTYPE/ENTITY refused")
    root = ET.fromstring(xml_text)

    def tag(e: ET.Element) -> str:
        return e.tag.split("}", 1)[-1]

    flat: dict[str, Any] = {}
    sysd = next((c for c in root if tag(c) == "System"), None)
    if sysd is not None:
        for c in sysd:
            t = tag(c)
            if t == "EventID":
                flat["EventID"] = _to_int(c.text)
            elif t == "EventRecordID":
                flat["RecordID"] = _to_int(c.text)
            elif t == "TimeCreated":
                flat["Time"] = c.attrib.get("SystemTime")
            elif t == "Computer":
                flat["Computer"] = (c.text or "").strip()
            elif t == "Channel":
                flat["Channel"] = (c.text or "").strip()
            elif t == "Provider":
                flat["Provider"] = c.attrib.get("Name", "")
    for ed in root:
        if tag(ed) in ("EventData", "UserData"):
            for d in ed.iter():
                n = d.attrib.get("Name")
                if n:
                    flat[n] = (d.text or "").strip()
    flat.setdefault("Computer", "")
    flat.setdefault("Channel", "")
    flat.setdefault("Provider", "")
    return flat


_TASK_CMD = re.compile(r"<Command>(.*?)</Command>.*?(?:<Arguments>(.*?)</Arguments>)?", re.S)


def event_from_flat(d: dict, event_id: str, raw_ref: str) -> tuple[Event, bool]:
    """flat dict -> (Event, classified?)."""
    eid = d["EventID"]
    chan = str(d.get("Channel", "")).lower()
    prov = str(d.get("Provider", "")).lower()
    sysmon = "sysmon" in chan or "sysmon" in prov
    name = SYSMON_NAMES.get(eid) if sysmon else SECURITY_NAMES.get(eid)
    classified = name is not None
    g = lambda k: d.get(k, "")  # noqa: E731
    user = ip = ""
    fields: dict[str, Any] = {}
    if sysmon:
        fields["via"] = "sysmon"
    if name in ("logon_success", "logon_failed", "logoff", "ntlm_credential_validation"):
        user = g("TargetUserName")
        ip = g("IpAddress")
        fields.update(domain=g("TargetDomainName"), logon_type=g("LogonType"), auth=g("AuthenticationPackageName"),
                      process=g("LogonProcessName"), workstation=g("WorkstationName") or g("Workstation"),
                      status=g("Status"), sub_status=g("SubStatus"))
    elif name == "explicit_credential_logon":
        user, ip = g("SubjectUserName"), g("IpAddress")
        fields.update(target_user=g("TargetUserName"), target_server=g("TargetServerName"))
    elif name == "special_privileges_assigned":
        user = g("SubjectUserName")
    elif name == "process_create":
        if sysmon:
            user = g("User")
            fields.update(image=g("Image"), parent=g("ParentImage"), cmd=g("CommandLine"))
        else:
            user = g("SubjectUserName")
            fields.update(image=g("NewProcessName"), parent=g("ParentProcessName"), cmd=g("CommandLine"))
    elif name == "network_connection":
        user = g("User")
        fields.update(image=g("Image"), dst=g("DestinationIp"), dport=g("DestinationPort"))
    elif name == "process_access":
        user = g("SourceUser")
        fields.update(source_image=g("SourceImage"), target_image=g("TargetImage"), access=g("GrantedAccess"))
    elif name == "file_create":
        user = g("User")
        fields.update(image=g("Image"), file=g("TargetFilename"))
    elif name == "service_installed":
        user = g("SubjectUserName")
        fields.update(service=g("ServiceName"), image=g("ServiceFileName") or g("ImagePath"),
                      start=g("StartType") or g("ServiceStartType"))
    elif name == "scheduled_task_created":
        user = g("SubjectUserName")
        cmd = ""
        m = _TASK_CMD.search(str(g("TaskContent")))
        if m:
            cmd = (m.group(1) + " " + (m.group(2) or "")).strip()
        fields.update(task=g("TaskName"), cmd=cmd)
    elif name == "account_created":
        user = g("SubjectUserName")
        fields.update(target=g("TargetUserName"))
    elif name == "group_member_added":
        user = g("SubjectUserName")
        fields.update(group=g("TargetUserName"), member=g("MemberName") or g("MemberSid"))
    elif name == "audit_log_cleared":
        user = g("SubjectUserName") or g("UserName")
    elif name in ("kerberos_tgt_request", "kerberos_service_ticket"):
        user, ip = g("TargetUserName"), g("IpAddress")
        fields.update(service=g("ServiceName"), enc=g("TicketEncryptionType"), status=g("Status"))
    elif name == "share_access":
        user, ip = g("SubjectUserName"), g("IpAddress")
        fields.update(share=g("ShareName"), path=g("ShareLocalPath"))
    else:
        name = f"windows_event_{eid}"
    # machine accounts (HOST$) are not human users
    if str(user).endswith("$"):
        fields["account"] = user
        user = ""
    ts = parse_ts(d["Time"])
    # free-text 'cmd' must stay last
    cmd = fields.pop("cmd", "")
    action = build_action(name, **fields, **({"cmd": cmd} if cmd else {}))
    return make_event(event_id, ts, "windows", g("Computer"), user, ip, action, raw_ref), classified


def iter_json_records(path: str) -> Iterator[tuple[Optional[dict], str, Optional[str]]]:
    """Yield (flat_or_None, locator, error) for a .json/.jsonl file ('line=N' for jsonl, 'index=N' for arrays)."""
    opener = _open_text(path)
    with opener as fh:
        head = fh.read(1)
        while head and head.isspace():
            head = fh.read(1)
        fh.seek(0)
        if head == "[":
            try:
                arr = json.load(fh)
            except json.JSONDecodeError as e:
                yield None, "index=0", f"invalid JSON: {e}"
                return
            for i, obj in enumerate(arr, 1):
                yield (flatten_windows(obj) if isinstance(obj, dict) else None), f"index={i}", None
        else:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as e:
                    yield None, f"line={n}", f"line {n}: invalid JSON ({e.msg})"
                    continue
                yield (flatten_windows(obj) if isinstance(obj, dict) else None), f"line={n}", None


def iter_evtx(path: str) -> Iterator[tuple[Optional[dict], str, Optional[str]]]:
    """Read a binary .evtx using the optional 'python-evtx' package (pip install python-evtx)."""
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise ImportError("Reading .evtx needs:  pip install python-evtx   (or convert to JSON first)") from e
    with Evtx(str(path)) as log:  # pragma: no cover
        for i, rec in enumerate(log.records(), 1):
            try:
                flat = flat_from_xml(rec.xml())
                yield flat, f"record={flat.get('RecordID') or i}", None
            except Exception as ex:
                yield None, f"record={i}", f"record {i}: {type(ex).__name__}: {ex}"


def _open_text(path: str):
    import gzip
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")

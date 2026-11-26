"""AWS CloudTrail parser ({"Records":[...]}, plain list, JSONL; .gz allowed)."""
from __future__ import annotations

import json
from typing import Any, Iterator, Optional

from vai.common.models import Event

from .common import build_action, clean_ip, make_event, parse_ts
from .parse_windows import _open_text

_PARAM_MAP = {"userName": "target_user", "policyArn": "policy", "secretId": "secret", "roleName": "role"}


def iter_cloudtrail(path: str) -> Iterator[tuple[Optional[dict], str, Optional[str]]]:
    """Yield (record_or_None, locator 'index=N', error)."""
    with _open_text(path) as fh:
        text = fh.read()
    stripped = text.lstrip()
    if not stripped:
        return
    try:
        if stripped[0] == "{" and '"Records"' in stripped[:2000]:
            records = json.loads(text)["Records"]
        elif stripped[0] == "[":
            records = json.loads(text)
        else:                                            # JSONL
            records = []
            for n, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        records.append(None)
    except (json.JSONDecodeError, KeyError) as e:
        yield None, "index=0", f"invalid CloudTrail JSON: {e}"
        return
    for i, rec in enumerate(records, 1):
        if isinstance(rec, dict):
            yield rec, f"index={i}", None
        else:
            yield None, f"index={i}", f"record {i}: not a JSON object"


def event_from_record(rec: dict, event_id: str, raw_ref: str) -> Event:
    ui = rec.get("userIdentity") or {}
    user = ui.get("userName") or ""
    arn = ui.get("arn") or ""
    if not user:
        if ui.get("type") == "Root":
            user = "root"
        elif "/" in arn:
            user = arn.rsplit("/", 1)[-1]
    service = str(rec.get("eventSource", "aws")).split(".", 1)[0]
    name = f"{service}:{rec.get('eventName', 'unknown')}"
    raw_ip = rec.get("sourceIPAddress", "")
    ip = clean_ip(raw_ip)
    req = rec.get("requestParameters") or {}
    resp = rec.get("responseElements") or {}
    fields: dict[str, Any] = {"access_key": ui.get("accessKeyId", "")}
    if isinstance(req, dict):
        fields["bucket"] = req.get("bucketName", "")
        fields["key"] = req.get("key", "")
        for k, label in _PARAM_MAP.items():
            if k in req:
                fields[label] = req[k]
        if service == "cloudtrail" and "name" in req:
            fields["trail"] = req["name"]
    if isinstance(resp, dict) and "ConsoleLogin" in resp:
        fields["result"] = resp["ConsoleLogin"]
    fields["error"] = rec.get("errorCode", "")
    fields["principal_type"] = ui.get("type", "")
    fields["via"] = "" if ip else raw_ip                      # e.g. 'ec2.amazonaws.com'
    fields["ua"] = str(rec.get("userAgent", ""))[:60]
    ts = parse_ts(rec["eventTime"])
    return make_event(event_id, ts, "aws", rec.get("awsRegion", ""), user, ip, build_action(name, **fields), raw_ref)

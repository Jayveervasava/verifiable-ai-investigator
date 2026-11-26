"""Linux auth.log / syslog parser (ISO-8601 and classic 'Mar 14 09:12:01' timestamps)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional
from zoneinfo import ZoneInfo

from .common import UTC, build_action, make_event, parse_ts
from vai.common.models import Event

_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}

_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_FAILED = re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)")
_PAM_SESSION = re.compile(r"^pam_unix\((?P<svc>[\w-]+):session\): session (?P<what>opened|closed) for user (?P<user>[^\s(]+)")
_SUDO = re.compile(r"^(?P<user>\S+)\s*:\s*(?:TTY=\S+\s*;\s*)?PWD=(?P<pwd>[^;]*);\s*USER=(?P<runas>[^;]*);\s*COMMAND=(?P<cmd>.*)$")
_USERADD = re.compile(r"^new user: name=(?P<user>[^,\s]+)")


def split_line(line: str, year: int, tz: str = "UTC") -> Optional[tuple[datetime, str, str, str]]:
    """-> (utc_dt, host, program, message) or None if the line is not a syslog line."""
    m = _ISO.match(line)
    if m:
        return parse_ts(m["ts"]), m["host"], m["prog"], m["msg"]
    m = _CLASSIC.match(line)
    if m:
        h, mi, s = (int(x) for x in m["time"].split(":"))
        dt = datetime(year, _MONTHS[m["mon"]], int(m["day"]), h, mi, s, tzinfo=ZoneInfo(tz))
        return dt.astimezone(UTC), m["host"], m["prog"], m["msg"]
    return None


def event_from_line(line: str, event_id: str, raw_ref: str, year: int, tz: str = "UTC") -> tuple[Optional[Event], bool]:
    """-> (Event or None if not syslog, classified?)."""
    parts = split_line(line, year, tz)
    if parts is None:
        return None, False
    dt, host, prog, msg = parts
    user = ip = ""
    classified = True
    if prog == "sshd":
        if m := _ACCEPTED.match(msg):
            user, ip = m["user"], m["ip"]
            action = build_action("ssh_accepted", method=m["method"], port=m["port"])
        elif m := _FAILED.match(msg):
            user, ip = m["user"], m["ip"]
            action = build_action("ssh_failed", method=m["method"], port=m["port"])
        elif m := _INVALID.match(msg):
            user, ip = m["user"], m["ip"]
            action = build_action("ssh_invalid_user")
        elif m := _PAM_SESSION.match(msg):
            user = m["user"]
            action = build_action(f"ssh_session_{m['what']}")
        else:
            action, classified = build_action("ssh_other", msg=msg[:120]), False
    elif prog == "sudo" and (m := _SUDO.match(msg)):
        user = m["user"]
        action = build_action("sudo_command", pwd=m["pwd"].strip(), run_as=m["runas"].strip(), cmd=m["cmd"].strip())
    elif prog.upper() == "CRON" and (m := _PAM_SESSION.match(msg)):
        user = m["user"]
        action = build_action(f"cron_session_{m['what']}")
    elif prog == "useradd" and (m := _USERADD.match(msg)):
        action = build_action("user_added", target=m["user"])
    else:
        action, classified = build_action("syslog_other", prog=prog, msg=msg[:120]), False
    return make_event(event_id, dt, "linux", host, user, ip, action, raw_ref), classified

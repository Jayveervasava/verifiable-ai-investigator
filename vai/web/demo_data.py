"""Synthetic demo evidence. All names, IPs and accounts are fictional.

Writes Event-format JSONL files (one per source) so the Evidence step has real files to hash.
Case 2 is a synthetic stand-in SHAPED like public data (EVTX-ATTACK-SAMPLES style Windows events and
the Stratus Red Team "share EBS snapshot" AWS technique). It is NOT copied from those datasets.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS documentation example key id (not a real key)

CASES = {
    "FIR-1427-2027": {
        "title": "FIR-1427/2027 \u00b7 Cloud data theft",
        "victim": "ABC Finserv Pvt Ltd",
        "officer": "SI R. Patel",
        "opened": "12 Mar 2027",
        "note": "Synthetic demo case 1 (all data invented).",
        "files": ["case1_windows.jsonl", "case1_linux.jsonl", "case1_aws.jsonl"],
    },
    "DEMO-PUBLIC-02": {
        "title": "DEMO-PUBLIC-02 \u00b7 Backup account misuse and snapshot sharing",
        "victim": "Example Logistics Ltd (fictional)",
        "officer": "SI R. Patel",
        "opened": "02 Apr 2027",
        "note": ("Synthetic stand-in shaped like public datasets (EVTX-ATTACK-SAMPLES, Stratus Red Team). "
                 "Real ingest of those datasets is pending (vai.evidence)."),
        "files": ["case2_windows.jsonl", "case2_aws.jsonl"],
    },
}

_USERS = ["a.shah", "k.desai", "r.mehta", "p.iyer", "s.nair", "m.joshi"]
_DAYS = ["2027-03-07", "2027-03-08", "2027-03-09", "2027-03-10"]
HOME_IP = "103.21.44.8"


def _ev(i, ts, source, host, user, ip, action):
    return {"id": i, "ts_utc": ts, "source": source, "host": host, "user": user, "ip": ip, "action": action}


def _case1():
    rnd = random.Random(1427)
    w, l, a = [], [], []
    n = 0
    for d in _DAYS:
        for u in _USERS:
            host = f"DESKTOP-FIN{_USERS.index(u) + 1:02d}"
            for k in range(3):  # logons
                n += 1
                if u == "r.mehta" and k == 0:
                    ip = HOME_IP
                    act = "logon_success type=10 (RemoteInteractive)"
                else:
                    ip = f"10.0.5.{10 + _USERS.index(u)}"
                    act = "logon_success type=2 (Interactive)"
                w.append(_ev(f"W-{n:05d}", f"{d}T0{8 + k}:{rnd.randint(10, 59)}:{rnd.randint(10, 59)}Z",
                             "windows", host, u, ip, act))
            for k in range(2):
                n += 1
                w.append(_ev(f"W-{n:05d}", f"{d}T1{k}:{rnd.randint(10, 59)}:{rnd.randint(10, 59)}Z", "windows",
                             host, u, f"10.0.5.{10 + _USERS.index(u)}",
                             rnd.choice(["file_access Q4_report.xlsx", "file_access payroll_march.xlsx"])))
        for u in ["a.shah", "k.desai", "r.mehta"]:
            n += 1
            l.append(_ev(f"L-{n:05d}", f"{d}T09:{rnd.randint(10, 59)}:{rnd.randint(10, 59)}Z", "linux",
                         "db-server-02", u, "10.0.7.21", "ssh_login_success"))
            for _ in range(2):
                n += 1
                l.append(_ev(f"L-{n:05d}", f"{d}T1{rnd.randint(0, 5)}:{rnd.randint(10, 59)}:{rnd.randint(10, 59)}Z",
                             "linux", "db-server-02", u, "10.0.7.21", "file_read /var/log/app.log"))
        for u in ["a.shah", "k.desai", "r.mehta", "p.iyer"]:
            for _ in range(3):
                n += 1
                a.append(_ev(f"A-{n:05d}", f"{d}T1{rnd.randint(0, 6)}:{rnd.randint(10, 59)}:{rnd.randint(10, 59)}Z",
                             "aws", "s3://abc-customer-data", u, HOME_IP,
                             f"s3:GetObject bucket=abc-customer-data object=report_{rnd.randint(1, 40)}.csv "
                             f"bytes={rnd.randint(2000, 90000)}"))
    atk_ip = "45.77.12.9"
    w += [
        _ev("W-10442", "2027-03-10T09:12:07Z", "windows", "DESKTOP-FIN07", "r.mehta", atk_ip,
            "logon_success type=10 (RemoteInteractive)"),
        _ev("W-10443", "2027-03-10T09:14:22Z", "windows", "DESKTOP-FIN07", "r.mehta", atk_ip, "rdp_session_start"),
    ]
    l += [
        _ev("L-3381", "2027-03-10T09:40:30Z", "linux", "db-server-02", "r.mehta", atk_ip, "ssh_login_success"),
        _ev("L-3396", "2027-03-10T09:50:02Z", "linux", "db-server-02", "r.mehta", atk_ip,
            "file_read ~/.aws/config"),
        _ev("L-3402", "2027-03-10T09:52:41Z", "linux", "db-server-02", "r.mehta", atk_ip,
            f"file_read ~/.aws/credentials key={KEY}"),
    ]
    sizes = [1_000_000_000, 900_000_000, 700_000_000, 500_000_000, 335_973_837]
    a += [
        _ev("A-9001", "2027-03-10T10:02:11Z", "aws", "aws-ap-south-1", "r.mehta", atk_ip,
            f"sts:GetCallerIdentity key={KEY}"),
        _ev("A-9010", "2027-03-10T10:03:20Z", "aws", "s3://abc-customer-data", "r.mehta", atk_ip,
            f"s3:ListBucket bucket=abc-customer-data key={KEY}"),
    ]
    for j, sz in enumerate(sizes):
        a.append(_ev(f"A-{9020 + j}", f"2027-03-10T10:05:{41 + j * 3:02d}Z", "aws", "s3://abc-customer-data",
                     "r.mehta", atk_ip,
                     f"s3:GetObject bucket=abc-customer-data object=customers_part{j + 1}.csv bytes={sz} key={KEY}"))
    return {"case1_windows.jsonl": w, "case1_linux.jsonl": l, "case1_aws.jsonl": a}


def _case2():
    rnd = random.Random(2)
    w, a = [], []
    n = 0
    for d in ["2027-03-30", "2027-03-31", "2027-04-01"]:
        for u in ["svc-backup", "t.rao", "n.kapoor"]:
            for k in range(3):
                n += 1
                w.append(_ev(f"W2-{n:04d}", f"{d}T0{6 + k}:{rnd.randint(10, 59)}:{rnd.randint(10, 59)}Z", "windows",
                             "SRV-BKP01" if u == "svc-backup" else "DESKTOP-OPS03", u, "10.20.5.8",
                             "logon_success type=3 (Network)"))
            n += 1
            a.append(_ev(f"A2-{n:04d}", f"{d}T0{rnd.randint(1, 5)}:{rnd.randint(10, 59)}:00Z", "aws",
                         "aws-ap-south-1", u if u == "svc-backup" else "t.rao", "198.51.100.17",
                         "ec2:DescribeSnapshots"))
    ip = "203.0.113.50"
    w += [
        _ev("W2-0412", "2027-04-02T01:12:09Z", "windows", "SRV-BKP01", "svc-backup", ip,
            "logon_success type=10 (RemoteInteractive)"),
        _ev("W2-0420", "2027-04-02T01:20:31Z", "windows", "SRV-BKP01", "svc-backup", "10.20.5.14",
            "lsass_access sysmon_event=10 target=lsass.exe"),
        _ev("W2-0433", "2027-04-02T01:33:48Z", "windows", "FS-02", "svc-backup", "10.20.5.14",
            "smb_admin_share_access share=ADMIN$"),
    ]
    a += [
        _ev("A2-5001", "2027-04-02T01:41:02Z", "aws", "aws-ap-south-1", "svc-backup", ip,
            "sts:GetCallerIdentity"),
        _ev("A2-5010", "2027-04-02T01:44:55Z", "aws", "aws-ap-south-1", "svc-backup", ip,
            "ec2:ModifySnapshotAttribute snapshot=snap-0demo1234 add_account=999999999999"),
    ]
    return {"case2_windows.jsonl": w, "case2_aws.jsonl": a}


def generate(folder: Path) -> dict[str, list[Path]]:
    """Write demo evidence files into `folder` (only if missing). Returns case_id -> [paths]."""
    folder.mkdir(parents=True, exist_ok=True)
    data = {**_case1(), **_case2()}
    for name, evs in data.items():
        p = folder / name
        if p.exists():
            continue
        evs = sorted(evs, key=lambda e: e["ts_utc"])
        with p.open("w", encoding="utf-8") as f:
            for i, e in enumerate(evs, start=1):
                e["raw_ref"] = f"{name}#L{i}"
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return {cid: [folder / n for n in meta["files"]] for cid, meta in CASES.items()}

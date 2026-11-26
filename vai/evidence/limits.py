"""Standard limitations of the evidence layer.  Claude 3 (agent) can attach these to every conclusion."""

EVIDENCE_LIMITATIONS = [
    "Only the log files supplied were examined; rotated, deleted or never-collected logs are not visible.",
    "Syslog lines without a timezone are assumed to be UTC (or the log_tz given at ingest); clocks of different hosts may be skewed.",
    "Records are linked by user name, IP address and AWS access key inside a time window; shared accounts, NAT or VPN addresses can create false links.",
    "'Unusual IP' is judged against the same dataset (an IP seen on 3+ different days for that user counts as usual); with short logs there may be no baseline.",
    "Technique tags are rule-based suggestions mapped to MITRE ATT&CK, not proof of intent; an analyst must confirm each one.",
    "Confidence 'high' means the same user and IP appear in 3 independent log sources; it does not prove the person behind the account.",
]

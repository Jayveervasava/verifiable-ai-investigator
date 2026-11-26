# case_public - demo case 2 (public-data style)

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

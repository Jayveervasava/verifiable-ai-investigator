"""Unit tests for the three parsers + helpers (small hand-made inputs)."""
import gzip
import json
import tempfile
from pathlib import Path


from vai.evidence import ingest, ingest_with_report, hash_files
from vai.evidence.common import clean_ip, get_field, is_external_ip, is_internal_ip, norm_user, parse_ts
from vai.evidence.parse_windows import flat_from_xml, event_from_flat

TMP = Path(tempfile.mkdtemp(prefix="vai_t_"))


def _write(name, text, mode="w"):
    p = TMP / name
    p.write_text(text, encoding="utf-8")
    return p


def test_helpers():
    assert norm_user("CORP\\R.Mehta") == "r.mehta" and norm_user("r.mehta@corp.local") == "r.mehta" and norm_user("-") == ""
    assert clean_ip("::ffff:45.77.12.9") == "45.77.12.9" and clean_ip("-") == "" and clean_ip("ec2.amazonaws.com") == ""
    assert clean_ip("1.2.3.4:5555") == "1.2.3.4"
    assert is_internal_ip("10.1.2.3") and is_internal_ip("::1") and not is_internal_ip("203.0.113.10")
    assert is_external_ip("45.77.12.9") and not is_external_ip("")
    assert parse_ts("2027-03-14T15:42:07.1234567Z").microsecond == 123456
    assert parse_ts("2027-03-14T21:12:07+05:30").hour == 15
    assert get_field("x | a=1 | cmd=foo bar | b=2", "cmd") == "foo bar"


def test_windows_json_4624_and_ids():
    rec = {"Event": {"System": {"EventID": 4624, "EventRecordID": 10442, "Computer": "WIN-FIN-01", "Channel": "Security",
                                "TimeCreated": {"#attributes": {"SystemTime": "2027-03-14T15:42:07.1230000Z"}}},
                     "EventData": {"TargetUserName": "R.Mehta", "TargetDomainName": "CORP", "LogonType": "10", "IpAddress": "45.77.12.9"}}}
    p = _write("w1.jsonl", json.dumps(rec) + "\n{broken json\n")
    evs, rep = ingest_with_report(p)
    assert len(evs) == 1 and rep["total_errors"] == 1            # bad line counted, not fatal
    e = evs[0]
    assert e.id == "W-10442" and e.source == "windows" and e.user == "r.mehta" and e.ip == "45.77.12.9" and e.host == "WIN-FIN-01"
    assert e.action.startswith("logon_success | ") and "logon_type=10" in e.action
    assert e.raw_ref == "w1.jsonl#line=1"


def test_windows_flat_and_array_and_unknown_id():
    arr = [{"EventID": 4625, "EventRecordID": 7, "TimeCreated": "2027-01-01T00:00:00Z", "Computer": "H", "TargetUserName": "x", "IpAddress": "-"},
           {"EventID": 9999, "EventRecordID": 8, "TimeCreated": "2027-01-01T00:00:01Z", "Computer": "H"}]
    p = _write("w2.json", json.dumps(arr))
    evs, rep = ingest_with_report(p)
    assert [e.id for e in evs] == ["W-7", "W-8"] and evs[0].ip == "" and evs[1].action.startswith("windows_event_9999")
    assert rep["total_unclassified"] == 1


def test_windows_xml_like_python_evtx():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
           '<EventID>4688</EventID><TimeCreated SystemTime="2027-03-14T15:43:17.5Z"/><EventRecordID>555</EventRecordID><Channel>Security</Channel>'
           '<Computer>WIN-FIN-01</Computer></System><EventData><Data Name="SubjectUserName">r.mehta</Data>'
           '<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">whoami /all</Data></EventData></Event>')
    flat = flat_from_xml(xml)
    ev, ok = event_from_flat(flat, "W-555", "x.evtx#record=555")
    assert ok and ev.user == "r.mehta" and ev.action.endswith("cmd=whoami /all")
    try:
        flat_from_xml('<!DOCTYPE x [<!ENTITY a "b">]><Event/>')
        assert False, "DOCTYPE must be refused"
    except ValueError:
        pass


def test_linux_iso_classic_sudo_and_line_ids():
    log = ("2027-03-14T15:51:33.000000+00:00 db-server-02 sshd[1]: Accepted password for r.mehta from 45.77.12.9 port 51122 ssh2\n"
           "\n"
           "2027-03-14T15:53:12+05:30 db-server-02 sudo: r.mehta : TTY=pts/0 ; PWD=/home/r.mehta ; USER=root ; COMMAND=/usr/bin/cat /home/r.mehta/.aws/credentials\n"
           "Mar 14 09:12:01 web-01 sshd[9]: Failed password for invalid user admin from 192.0.2.101 port 4000 ssh2\n"
           "garbage line\n"
           "2027-03-14T15:55:00Z web-01 kernel: something odd\n")
    p = _write("auth.log", log)
    evs, rep = ingest_with_report(p, year=2027)
    by = {e.id: e for e in evs}
    assert set(by) == {"L-1", "L-3", "L-4", "L-6"} and rep["total_errors"] == 1
    assert by["L-1"].action.startswith("ssh_accepted") and by["L-1"].ip == "45.77.12.9"
    assert by["L-3"].user == "r.mehta" and by["L-3"].ts_utc.hour == 10 and ".aws/credentials" in by["L-3"].action   # +05:30 -> UTC
    assert by["L-4"].action.startswith("ssh_failed") and by["L-4"].user == "admin"
    assert by["L-6"].action.startswith("syslog_other") and rep["total_unclassified"] == 1


def test_linux_ids_continue_across_files():
    a = _write("a1.log", "2027-01-01T00:00:00Z h sshd[1]: Accepted password for u from 1.1.1.1 port 1 ssh2\n")
    b = _write("a2.log", "2027-01-01T00:00:01Z h sshd[1]: Accepted password for u from 1.1.1.1 port 1 ssh2\n")
    assert [e.id for e in ingest([a, b])] == ["L-1", "L-2"]


def test_cloudtrail_s3_getobject_and_gz():
    rec = {"eventTime": "2027-03-14T16:02:07Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "awsRegion": "ap-south-1",
           "sourceIPAddress": "45.77.12.9", "userAgent": "aws-cli/2",
           "userIdentity": {"type": "IAMUser", "userName": "r.mehta", "accessKeyId": "AKIASYNTH1427001WXYZ"},
           "requestParameters": {"bucketName": "kyc", "key": "a.pdf"}}
    svc = dict(rec, eventName="DescribeInstances", eventSource="ec2.amazonaws.com", sourceIPAddress="lambda.amazonaws.com")
    p = _write("ct.json", json.dumps({"Records": [rec, svc]}))
    evs = ingest(p)
    assert [e.id for e in evs] == ["A-1", "A-2"]
    assert evs[0].action.startswith("s3:GetObject") and get_field(evs[0].action, "access_key") == "AKIASYNTH1427001WXYZ"
    assert evs[1].ip == "" and "via=lambda.amazonaws.com" in evs[1].action
    gz = TMP / "ct2.json.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({"Records": [rec]}))
    assert len(ingest(gz)) == 1


def test_unknown_file_skipped_and_hashes():
    p = _write("notes.json", '{"hello": "world"}')
    evs, rep = ingest_with_report(p)
    assert evs == [] and rep["files"][0]["kind"] is None and len(hash_files(p)[str(p)]) == 64


def test_missing_path_raises():
    try:
        ingest(TMP / "nope.log")
        assert False
    except FileNotFoundError:
        pass

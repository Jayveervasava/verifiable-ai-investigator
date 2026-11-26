"""Tests for vai.legal.mapping (MITRE -> IT Act / BNS)."""
import copy

from vai.legal import mapping
from vai.legal._compat import STATUS_TEXT

REQUIRED = ["T1078", "T1021", "T1530", "T1110", "T1566", "T1486", "T1048", "T1059", "T1098", "T1005"]


def test_shipped_file_is_valid():
    assert mapping.validate_mapping(mapping.load_mapping()) == []


def test_all_required_techniques_have_entries():
    for tid in REQUIRED:
        assert len(mapping.map_techniques([tid])) >= 1, tid


def test_every_match_is_suggestion_with_official_source():
    for m in mapping.map_techniques(REQUIRED):
        assert m.status == STATUS_TEXT == "suggested - officer confirms"
        assert m.source_url.startswith("https://www.indiacode.nic.in/")
        assert m.act in ("IT Act 2000", "BNS 2023")
        assert m.section and len(m.reason) > 30 and m.offence


def test_spot_checks_demo_case_techniques():
    def sections(tid):
        return {(m.act, m.section) for m in mapping.map_techniques([tid])}
    assert ("IT Act 2000", "66C") in sections("T1078")
    assert ("IT Act 2000", "43(b)") in sections("T1530")
    assert ("IT Act 2000", "43(a)") in sections("T1021")
    assert ("BNS 2023", "308") in sections("T1486")
    assert ("BNS 2023", "318(4)") in sections("T1566")


def test_order_dedupe_and_subtechnique():
    out = mapping.map_techniques(["T1078", "T1078.004", "t1078", "T1530"])
    assert [m.technique_id for m in out][0] == "T1078"
    assert out[-1].technique_id == "T1530"
    assert len({(m.technique_id, m.section, m.act) for m in out}) == len(out)


def test_unknown_technique_gives_nothing_and_is_reported():
    assert mapping.map_techniques(["T9999"]) == []
    assert mapping.unmapped(["T1078", "T9999"]) == ["T9999"]
    assert mapping.map_techniques([]) == []


def test_validator_catches_problems():
    data = copy.deepcopy(mapping.load_mapping())
    data["techniques"]["T1078"]["entries"][0]["source_url"] = "https://example.com/x"
    data["techniques"]["T1005"]["entries"][0]["reason"] = ""
    del data["techniques"]["T1486"]
    problems = " | ".join(mapping.validate_mapping(data))
    assert "indiacode" in problems and "reason" in problems and "T1486" in problems


def test_honesty_words_and_doubts():
    text = mapping.DATA_FILE.read_text(encoding="utf-8").lower()
    assert "admissible" not in text
    assert len(mapping.global_doubts()) >= 5
    assert "not reviewed by a lawyer" in text
    assert mapping.doubt_for("T1078", "IT Act 2000", "66C") != ""
    assert len(mapping.mapping_sha256()) == 64

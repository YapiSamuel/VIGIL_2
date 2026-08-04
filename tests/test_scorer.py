from dataclasses import dataclass
from typing import Optional

from vigil.scorer import score
from vigil.static_analyzer import Finding
from vigil.ioc_extractor import IOC, IOCHit


def mk_finding(name="reverse_shell_bash", category="c2", severity="high",
               layer_id=0, attack_id="T1071"):
    return Finding(name=name, engine="pattern", category=category,
                   matched="x", layer_id=layer_id, layer_technique="source",
                   attack_id=attack_id, severity=severity)


@dataclass
class FakeIntel:
    source: str
    indicator: str
    malicious: bool
    score: Optional[int] = None
    note: str = ""


def test_empty_signals_is_safe():
    s = score([], [], 0, [])
    assert s.value == 0
    assert s.band == "SAFE"
    assert not s.escalate
    assert s.notes  # notes that absence != safety


def test_high_severity_c2_finding_raises_band():
    s = score([mk_finding()], [], 0, [])
    assert s.value > 0
    assert any(item.source == "static" for item in s.items)


def test_determinism_same_inputs_same_score():
    findings = [mk_finding(), mk_finding(name="credential_dumping",
                                         category="credential_access")]
    iocs = [IOC("203.0.113.1", "ipv4", [IOCHit(0, "source")])]
    a = score(findings, iocs, 2, [])
    b = score(findings, iocs, 2, [])
    assert a.value == b.value and a.band == b.band


def test_obfuscation_depth_contributes():
    shallow = score([mk_finding()], [], 0, [])
    deep = score([mk_finding()], [], 3, [])
    assert deep.value > shallow.value
    assert any(i.source == "obfuscation" for i in deep.items)


def test_vt_intel_pushes_to_malicious():
    intel = [FakeIntel("virustotal", "a" * 64, True, score=45,
                       note="45/70 engines flagged")]
    s = score([mk_finding()], [], 1, intel)
    assert s.band in ("HIGH", "MALICIOUS")
    assert s.escalate
    assert any(i.source == "intel" for i in s.items)


def test_repeated_rule_counted_once_but_noted():
    findings = [mk_finding(layer_id=0), mk_finding(layer_id=1),
                mk_finding(layer_id=2)]
    s = score(findings, [], 0, [])
    static_items = [i for i in s.items if i.source == "static"]
    assert len(static_items) == 1
    assert "seen in 3 layers" in static_items[0].reason


def test_score_is_clamped_to_100():
    findings = [mk_finding(name=f"r{i}", severity="high", category="c2")
                for i in range(20)]
    intel = [FakeIntel("virustotal", "a" * 64, True, score=50)]
    s = score(findings, [], 8, intel)
    assert s.value <= 100


def test_every_item_cites_a_signal():
    findings = [mk_finding()]
    iocs = [IOC("203.0.113.1", "ipv4", [IOCHit(0, "source")], defanged=True)]
    s = score(findings, iocs, 2, [])
    for item in s.items:
        assert item.signal  # provenance is mandatory

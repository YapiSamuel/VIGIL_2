from vigil.scorer import score, Score, ScoreItem
from vigil.static_analyzer import Finding
from vigil.ioc_extractor import IOC, IOCHit
from vigil import verdict as vmod


def mk_finding():
    return Finding("reverse_shell_bash", "pattern", "c2", "bash -i", 1,
                   "base64", "T1071", "high")


def test_template_used_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    s = score([mk_finding()], [], 2, [])
    v = vmod.explain(s, findings=[mk_finding()], iocs=[], use_ai=True)
    assert v.source == "template"
    assert v.explanation
    assert any("no ANTHROPIC_API_KEY" in n for n in v.notes)


def test_verdict_does_not_change_score(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    s = score([mk_finding()], [], 2, [])
    v = vmod.explain(s, findings=[mk_finding()], iocs=[])
    assert v.band == s.band
    assert v.score == s.value
    assert v.escalate == s.escalate


def test_empty_evidence_explanation_is_honest(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    s = score([], [], 0, [])
    v = vmod.explain(s, findings=[], iocs=[])
    assert "not proof of safety" in v.explanation.lower()
    assert v.confidence == "low"


def test_attack_ids_collected():
    s = score([mk_finding()], [], 1, [])
    v = vmod.explain(s, findings=[mk_finding()], iocs=[], use_ai=False)
    assert "T1071" in v.attack_ids


def test_confidence_high_with_intel():
    from dataclasses import dataclass

    @dataclass
    class FakeIntel:
        source: str = "virustotal"
        malicious: bool = True
    s = Score(value=90, band="MALICIOUS", escalate=True,
              items=[ScoreItem(45, "VT", "virustotal:x", "intel")])
    v = vmod.explain(s, findings=[], iocs=[], intel_results=[FakeIntel()],
                     use_ai=False)
    assert v.confidence == "high"


def test_ai_path_falls_back_on_error(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake")
    # force the anthropic call to fail internally -> fallback to template
    monkeypatch.setattr(vmod, "_anthropic_explanation", lambda *a, **k: None)
    s = score([mk_finding()], [], 1, [])
    v = vmod.explain(s, findings=[mk_finding()], iocs=[])
    assert v.source == "template"
    assert any("AI narration unavailable" in n for n in v.notes)


def test_template_names_iocs(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    iocs = [IOC("http://evil.example/x", "url", [IOCHit(1, "base64")])]
    s = score([mk_finding()], iocs, 1, [])
    v = vmod.explain(s, findings=[mk_finding()], iocs=iocs, use_ai=False)
    assert "evil.example" in v.explanation

